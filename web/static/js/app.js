/**
 * QuantumShield frontend runtime: theme + global UX helpers.
 */

document.addEventListener('DOMContentLoaded', () => {
    const THEME_KEY = 'qss_theme';
    const MOBILE_NAV_BREAKPOINT = 900;
    const root = document.documentElement;
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
    }

    const saved = localStorage.getItem(THEME_KEY) || root.getAttribute('data-theme') || 'system';
    applyTheme(saved);

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
        const dropdowns = Array.from(navLinks.querySelectorAll('.nav-dropdown'));

        const closeDropdowns = () => {
            dropdowns.forEach((dropdown) => {
                dropdown.classList.remove('mobile-open');
                const trigger = dropdown.querySelector('.nav-dropdown-trigger');
                if (trigger) {
                    trigger.setAttribute('aria-expanded', 'false');
                }
            });
        };

        const closeNav = () => {
            navLinks.classList.remove('nav-open');
            navBtn.setAttribute('aria-expanded', 'false');
            closeDropdowns();
        };

        dropdowns.forEach((dropdown) => {
            const trigger = dropdown.querySelector('.nav-dropdown-trigger');
            if (!trigger) {
                return;
            }

            trigger.setAttribute('aria-expanded', 'false');

            trigger.addEventListener('click', (evt) => {
                if (window.innerWidth > MOBILE_NAV_BREAKPOINT) {
                    return;
                }
                evt.preventDefault();
                evt.stopPropagation();

                const isOpen = dropdown.classList.contains('mobile-open');
                closeDropdowns();
                if (!isOpen) {
                    dropdown.classList.add('mobile-open');
                    trigger.setAttribute('aria-expanded', 'true');
                }
            });
        });

        navLinks.querySelectorAll('a, button:not(.nav-dropdown-trigger)').forEach((el) => {
            el.addEventListener('click', () => {
                if (window.innerWidth <= MOBILE_NAV_BREAKPOINT) {
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
            if (window.innerWidth <= MOBILE_NAV_BREAKPOINT && navLinks.classList.contains('nav-open')) {
                if (!navLinks.contains(target) && !navBtn.contains(target)) {
                    closeNav();
                }
            }
        });

        window.addEventListener('resize', () => {
            if (window.innerWidth > MOBILE_NAV_BREAKPOINT) {
                closeNav();
            }
        });
    }
});
