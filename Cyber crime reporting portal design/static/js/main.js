/**
 * CyberSafe India — Main JavaScript
 */
document.addEventListener('DOMContentLoaded', () => {

    // ─── Mobile Nav Toggle ──────────────────────────────────
    const toggle = document.getElementById('nav-toggle');
    const navLinks = document.getElementById('nav-links');
    if (toggle && navLinks) {
        toggle.addEventListener('click', () => {
            navLinks.classList.toggle('active');
            toggle.classList.toggle('active');
        });
    }

    // ─── Navbar Scroll Effect ───────────────────────────────
    const navbar = document.getElementById('main-navbar');
    if (navbar) {
        window.addEventListener('scroll', () => {
            navbar.classList.toggle('scrolled', window.scrollY > 50);
        });
    }

    // ─── Flash Message Auto-dismiss ─────────────────────────
    document.querySelectorAll('.flash-message').forEach((msg) => {
        setTimeout(() => {
            msg.style.animation = 'slideOut 0.4s ease forwards';
            setTimeout(() => msg.remove(), 400);
        }, 5000);
    });

    // ─── Scroll Reveal Animations ───────────────────────────
    const observerOpts = { threshold: 0.1, rootMargin: '0px 0px -50px 0px' };
    const revealObserver = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('revealed');
                revealObserver.unobserve(entry.target);
            }
        });
    }, observerOpts);

    document.querySelectorAll('.category-card, .case-card, .stat-card, .awareness-card, .form-feature').forEach(el => {
        el.classList.add('reveal');
        revealObserver.observe(el);
    });

    // ─── Alert Ticker Animation ─────────────────────────────
    const tickerContent = document.getElementById('ticker-content');
    if (tickerContent) {
        // Clone content for seamless loop
        const clone = tickerContent.innerHTML;
        tickerContent.innerHTML = clone + clone;
    }

    // ─── Parallax for Hero ──────────────────────────────────
    const hero = document.getElementById('hero-section');
    if (hero) {
        window.addEventListener('scroll', () => {
            const scroll = window.scrollY;
            hero.style.transform = `translateY(${scroll * 0.3}px)`;
            hero.style.opacity = 1 - scroll / 800;
        });
    }

    // ─── Form Validation Feedback ───────────────────────────
    document.querySelectorAll('form').forEach(form => {
        form.querySelectorAll('input, select, textarea').forEach(input => {
            input.addEventListener('blur', () => {
                if (input.required && !input.value.trim()) {
                    input.classList.add('input-error');
                } else {
                    input.classList.remove('input-error');
                }
            });
            input.addEventListener('input', () => input.classList.remove('input-error'));
        });
    });
});
