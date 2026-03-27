
asset inventory page should have a table listing all assets with columns for asset name, asset type, risk score, last scan date, and actions (view details, edit, delete). The page should also include filters for asset type and risk score, as well as a search bar for quick asset lookup. For empty states, display a message like "No assets found. Please add assets to the inventory." The design should be consistent with the modern dark glassmorphism style used throughout the application. anything in the table should be clickable to view more details about the asset, and there should be clear calls to action for editing or deleting assets. The page should also include pagination if there are a large number of assets in the inventory. the asset inventory 
page should support real-time data fetching via API endpoints:
- `GET /api/assets` (with query params for filters, search, pagination)
- `GET /api/assets/{id}` (for detail view)
- `DELETE /api/assets/{id}` (for deletion)
- `PUT /api/assets/{id}` (for edits)

All table rows, filter dropdowns, and search inputs must be wired to actual API calls with proper error handling, loading states, and validation. No seeded or mock data—only persisted database results. Include skeleton loaders during fetch, empty state when API returns zero results, and error alerts if API calls fail.