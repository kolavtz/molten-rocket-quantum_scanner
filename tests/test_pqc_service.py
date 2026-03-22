"""Unit tests for PQCService.

Validates:
- Asset-based aggregation (not scan-based)
- Soft-delete filtering (is_deleted=False)
- Correct percentage calculations
- Risk heatmap generation
- Recommendation building
- Empty state handling
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from src.services.pqc_service import PQCService
from src.models import Asset, PQCClassification, Scan


class TestPQCServiceEmptyState:
    """Test PQCService with no assets or PQC data."""

    @patch('src.services.pqc_service.db_session')
    def test_empty_asset_inventory(self, mock_db):
        """When no assets exist, return empty state."""
        # Mock query to return empty assets
        mock_query = MagicMock()
        mock_query.filter.return_value.all.return_value = []
        mock_db.query.return_value = mock_query

        result = PQCService.get_pqc_dashboard_data()

        assert result['meta']['total_assets'] == 0
        assert result['kpis']['elite_pct'] == 0
        assert result['kpis']['critical_count'] == 0
        assert len(result['applications']) == 0
        assert result['recommendations'] == ["Run scans to populate PQC posture."]


class TestPQCServiceAssetAggregation:
    """Test that PQCService aggregates by asset, not scan."""

    @patch('src.services.pqc_service.db_session')
    def test_multiple_pqc_records_per_asset(self, mock_db):
        """Asset with multiple PQC classifications uses best score."""
        # Create mock asset
        asset1 = Mock(spec=Asset)
        asset1.id = 1
        asset1.target = "example.com"
        asset1.name = "example.com"

        # Create mock PQC classifications (multiple per asset)
        pqc1 = Mock(spec=PQCClassification)
        pqc1.asset_id = 1
        pqc1.pqc_score = 85  # Best score
        pqc1.quantum_safe_status = "quantum_safe"
        pqc1.asset = asset1

        pqc2 = Mock(spec=PQCClassification)
        pqc2.asset_id = 1
        pqc2.pqc_score = 70  # Lower score, same asset
        pqc2.quantum_safe_status = "quantum_safe"
        pqc2.asset = asset1

        # Mock db queries
        def mock_query_side_effect(model):
            if model == Asset:
                query_mock = MagicMock()
                query_mock.filter.return_value.all.return_value = [asset1]
                return query_mock
            elif model == PQCClassification:
                query_mock = MagicMock()
                query_mock.filter.return_value.order_by.return_value.all.return_value = [pqc1, pqc2]
                return query_mock

        mock_db.query.side_effect = mock_query_side_effect

        result = PQCService.get_pqc_dashboard_data()

        # Asset should be counted once, in "Elite" tier (85 >= 80)
        assert result['grade_counts']['Elite'] == 1
        assert result['meta']['total_assets'] == 1
        # Only one application row (asset-based, not pqc record-based)
        assert len(result['applications']) == 1


class TestPQCServiceSoftDeleteFiltering:
    """Test that PQCService filters is_deleted=False."""

    @patch('src.services.pqc_service.db_session')
    def test_deleted_assets_excluded(self, mock_db):
        """Deleted assets should not be counted in metrics."""
        # Create mock assets: one active, one deleted
        active_asset = Mock(spec=Asset)
        active_asset.id = 1
        active_asset.target = "active.com"
        active_asset.name = "active.com"
        active_asset.is_deleted = False

        deleted_asset = Mock(spec=Asset)
        deleted_asset.id = 2
        deleted_asset.target = "deleted.com"
        deleted_asset.name = "deleted.com"
        deleted_asset.is_deleted = True

        pqc_active = Mock(spec=PQCClassification)
        pqc_active.asset_id = 1
        pqc_active.pqc_score = 85
        pqc_active.quantum_safe_status = "quantum_safe"
        pqc_active.asset = active_asset

        def mock_query_side_effect(model):
            if model == Asset:
                query_mock = MagicMock()
                query_mock.filter.return_value.all.return_value = [active_asset]
                return query_mock
            elif model == PQCClassification:
                query_mock = MagicMock()
                query_mock.filter.return_value.order_by.return_value.all.return_value = [pqc_active]
                return query_mock

        mock_db.query.side_effect = mock_query_side_effect

        result = PQCService.get_pqc_dashboard_data()

        # Only active asset should be counted
        assert result['meta']['total_assets'] == 1
        assert result['grade_counts']['Elite'] == 1


class TestPQCServicePercentageCalculations:
    """Test correct percentage calculations based on asset counts."""

    @patch('src.services.pqc_service.db_session')
    def test_percentage_calculation_elite(self, mock_db):
        """Elite percentage should be (elite_count / total_assets) * 100."""
        # Create 10 mock assets: 8 Elite, 2 Standard
        assets = []
        pqc_records = []

        for i in range(10):
            asset = Mock(spec=Asset)
            asset.id = i
            asset.target = f"asset{i}.com"
            asset.name = f"asset{i}.com"
            assets.append(asset)

            pqc = Mock(spec=PQCClassification)
            pqc.asset_id = i
            pqc.asset = asset
            pqc.quantum_safe_status = "quantum_safe"

            # 8 Elite (score >= 80), 2 Standard (score >= 60)
            if i < 8:
                pqc.pqc_score = 85
            else:
                pqc.pqc_score = 65

            pqc_records.append(pqc)

        def mock_query_side_effect(model):
            if model == Asset:
                query_mock = MagicMock()
                query_mock.filter.return_value.all.return_value = assets
                return query_mock
            elif model == PQCClassification:
                query_mock = MagicMock()
                query_mock.filter.return_value.order_by.return_value.all.return_value = pqc_records
                return query_mock

        mock_db.query.side_effect = mock_query_side_effect

        result = PQCService.get_pqc_dashboard_data()

        # Elite: 8/10 * 100 = 80%
        # Standard: 2/10 * 100 = 20%
        assert result['kpis']['elite_pct'] == 80.0
        assert result['kpis']['standard_pct'] == 20.0
        assert result['kpis']['legacy_pct'] == 0.0


class TestPQCServiceRiskHeatmap:
    """Test risk heatmap generation."""

    @patch('src.services.pqc_service.db_session')
    def test_heatmap_counts_by_tier(self, mock_db):
        """Heatmap should show asset counts per tier."""
        # Create 5 Elite, 3 Standard
        assets = []
        pqc_records = []

        for i in range(8):
            asset = Mock(spec=Asset)
            asset.id = i
            asset.target = f"asset{i}.com"
            asset.name = f"asset{i}.com"
            assets.append(asset)

            pqc = Mock(spec=PQCClassification)
            pqc.asset_id = i
            pqc.asset = asset
            pqc.quantum_safe_status = "quantum_safe"
            pqc.pqc_score = 85 if i < 5 else 65
            pqc_records.append(pqc)

        def mock_query_side_effect(model):
            if model == Asset:
                query_mock = MagicMock()
                query_mock.filter.return_value.all.return_value = assets
                return query_mock
            elif model == PQCClassification:
                query_mock = MagicMock()
                query_mock.filter.return_value.order_by.return_value.all.return_value = pqc_records
                return query_mock

        mock_db.query.side_effect = mock_query_side_effect

        result = PQCService.get_pqc_dashboard_data()

        heatmap = result['risk_heatmap']
        assert len(heatmap) == 4  # Elite, Standard, Legacy, Critical

        # Find Elite and Standard cells
        elite_cell = next(h for h in heatmap if h['y'] == 'Elite')
        standard_cell = next(h for h in heatmap if h['y'] == 'Standard')

        assert elite_cell['value'] == 5
        assert standard_cell['value'] == 3


class TestPQCServiceRecommendations:
    """Test recommendation building based on posture."""

    @patch('src.services.pqc_service.db_session')
    def test_recommendations_include_critical_apps(self, mock_db):
        """When critical apps exist, recommendation should mention them."""
        # Create 2 Critical assets
        assets = []
        pqc_records = []

        for i in range(2):
            asset = Mock(spec=Asset)
            asset.id = i
            asset.target = f"critical{i}.com"
            asset.name = f"critical{i}.com"
            assets.append(asset)

            pqc = Mock(spec=PQCClassification)
            pqc.asset_id = i
            pqc.asset = asset
            pqc.quantum_safe_status = "quantum_vulnerable"
            pqc.pqc_score = 30  # Critical (< 40)
            pqc_records.append(pqc)

        def mock_query_side_effect(model):
            if model == Asset:
                query_mock = MagicMock()
                query_mock.filter.return_value.all.return_value = assets
                return query_mock
            elif model == PQCClassification:
                query_mock = MagicMock()
                query_mock.filter.return_value.order_by.return_value.all.return_value = pqc_records
                return query_mock

        mock_db.query.side_effect = mock_query_side_effect

        result = PQCService.get_pqc_dashboard_data()

        recs = result['recommendations']
        assert any('Critical' in rec for rec in recs)
        assert any('2' in rec for rec in recs)


class TestPQCServiceApplicationsTable:
    """Test applications (asset-based) table generation."""

    @patch('src.services.pqc_service.db_session')
    def test_applications_show_asset_rows(self, mock_db):
        """Applications should be one row per asset, not per PQC record."""
        # Single asset with 3 PQC classifications
        asset = Mock(spec=Asset)
        asset.id = 1
        asset.target = "example.com"
        asset.name = "example.com"

        pqc1 = Mock(spec=PQCClassification)
        pqc1.asset_id = 1
        pqc1.pqc_score = 85
        pqc1.quantum_safe_status = "quantum_safe"
        pqc1.asset = asset

        pqc2 = Mock(spec=PQCClassification)
        pqc2.asset_id = 1
        pqc2.pqc_score = 80
        pqc2.quantum_safe_status = "quantum_safe"
        pqc2.asset = asset

        pqc3 = Mock(spec=PQCClassification)
        pqc3.asset_id = 1
        pqc3.pqc_score = 90
        pqc3.quantum_safe_status = "quantum_safe"
        pqc3.asset = asset

        def mock_query_side_effect(model):
            if model == Asset:
                query_mock = MagicMock()
                query_mock.filter.return_value.all.return_value = [asset]
                return query_mock
            elif model == PQCClassification:
                query_mock = MagicMock()
                query_mock.filter.return_value.order_by.return_value.all.return_value = [pqc1, pqc2, pqc3]
                return query_mock

        mock_db.query.side_effect = mock_query_side_effect

        result = PQCService.get_pqc_dashboard_data()

        # Should have 1 application row (asset-based), not 3
        apps = result['applications']
        assert len(apps) == 1
        assert apps[0]['target'] == "example.com"
        assert apps[0]['status'] == 'Elite'  # 85 >= 80


class TestPQCServiceTierMapping:
    """Test conversion of scores to tiers."""

    def test_score_to_tier_elite(self):
        """Score >= 80 -> Elite."""
        assert PQCService._score_to_pqc_tier(80) == "Elite"
        assert PQCService._score_to_pqc_tier(100) == "Elite"

    def test_score_to_tier_standard(self):
        """Score >= 60 and < 80 -> Standard."""
        assert PQCService._score_to_pqc_tier(60) == "Standard"
        assert PQCService._score_to_pqc_tier(79) == "Standard"

    def test_score_to_tier_legacy(self):
        """Score >= 40 and < 60 -> Legacy."""
        assert PQCService._score_to_pqc_tier(40) == "Legacy"
        assert PQCService._score_to_pqc_tier(59) == "Legacy"

    def test_score_to_tier_critical(self):
        """Score < 40 -> Critical."""
        assert PQCService._score_to_pqc_tier(0) == "Critical"
        assert PQCService._score_to_pqc_tier(39) == "Critical"

    def test_score_to_tier_null(self):
        """None/null score -> Critical."""
        assert PQCService._score_to_pqc_tier(None) == "Critical"


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
