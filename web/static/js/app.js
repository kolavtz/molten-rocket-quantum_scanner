/**
 * QuantumShield frontend runtime: theme + global UX helpers.
 */

document.addEventListener('DOMContentLoaded', () => {
    const THEME_KEY = 'qss_theme';
    const root = document.documentElement;
    const toggle = document.getElementById('themeToggle');
    const systemPrefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)');

    function resolveTheme(pref) {
        if (pref === 'light' || pref === 'dark') {
            return pref;
        }
        return systemPrefersDark && systemPrefersDark.matches ? 'dark' : 'light';
    }

    function applyTheme(pref) {
        const mode = resolveTheme(pref);
        root.setAttribute('data-theme', mode);
        if (toggle) {
            toggle.textContent = mode === 'dark' ? 'LIGHT MODE' : 'NIGHT MODE';
            toggle.setAttribute('aria-pressed', mode === 'dark' ? 'true' : 'false');
        }
    }

    const saved = localStorage.getItem(THEME_KEY) || 'system';
    applyTheme(saved);

    if (toggle) {
        toggle.addEventListener('click', () => {
            const current = root.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
            const next = current === 'dark' ? 'light' : 'dark';
            localStorage.setItem(THEME_KEY, next);
            applyTheme(next);
        });
    }

    if (systemPrefersDark && systemPrefersDark.addEventListener) {
        systemPrefersDark.addEventListener('change', () => {
            const stored = localStorage.getItem(THEME_KEY) || 'system';
            if (stored === 'system') {
                applyTheme('system');
            }
        });
    }

    // Mobile nav behavior.
    const navBtn = document.getElementById('navHamburger');
    const navLinks = document.getElementById('navLinks');
    if (navBtn && navLinks) {
        const closeNav = () => {
            navLinks.classList.remove('nav-open');
            navBtn.setAttribute('aria-expanded', 'false');
        };

        navLinks.querySelectorAll('a, button').forEach((el) => {
            el.addEventListener('click', () => {
                if (window.innerWidth <= 768) {
                    closeNav();
                }
            });
        });

        document.addEventListener('keydown', (evt) => {
            if (evt.key === 'Escape') {
                closeNav();
            }
        });

        document.addEventListener('click', (evt) => {
            const target = evt.target;
            if (!(target instanceof Element)) {
                return;
            }
            if (window.innerWidth <= 768 && navLinks.classList.contains('nav-open')) {
                if (!navLinks.contains(target) && !navBtn.contains(target)) {
                    closeNav();
                }
            }
        });
    }
});
