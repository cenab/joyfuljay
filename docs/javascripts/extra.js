/**
 * JoyfulJay Documentation - Custom JavaScript
 */

(function() {
  'use strict';

  // =====================================================
  // Feature Search Enhancement
  // =====================================================

  /**
   * Initialize feature search with autocomplete
   */
  function initFeatureSearch() {
    const searchInput = document.querySelector('.md-search__input');
    if (!searchInput) return;

    // Feature names for autocomplete suggestions
    const featureNames = [
      'iat_mean', 'iat_std', 'iat_min', 'iat_max',
      'pkt_len_mean', 'pkt_len_std', 'pkt_len_min', 'pkt_len_max',
      'ja3_hash', 'ja3s_hash', 'sni', 'tls_version',
      'hassh_hash', 'hassh_server_hash',
      'likely_tor', 'likely_vpn', 'likely_doh',
      'flow_duration', 'total_packets', 'total_bytes'
    ];

    // Add feature-specific search hints
    searchInput.addEventListener('focus', function() {
      const hint = document.createElement('div');
      hint.className = 'search-hint';
      hint.textContent = 'Tip: Search for feature names like "ja3_hash" or "iat_mean"';
      hint.style.cssText = 'font-size: 0.75em; color: var(--md-default-fg-color--light); padding: 0.5em;';

      const existingHint = document.querySelector('.search-hint');
      if (!existingHint) {
        searchInput.parentNode.appendChild(hint);

        setTimeout(() => {
          hint.remove();
        }, 5000);
      }
    });
  }

  // =====================================================
  // Code Copy Enhancement
  // =====================================================

  /**
   * Add copy feedback animation
   */
  function initCopyFeedback() {
    document.querySelectorAll('.md-clipboard').forEach(button => {
      button.addEventListener('click', function() {
        const feedback = document.createElement('span');
        feedback.textContent = 'Copied!';
        feedback.className = 'copy-feedback';
        feedback.style.cssText = `
          position: absolute;
          background: var(--md-primary-fg-color);
          color: white;
          padding: 0.25em 0.5em;
          border-radius: 4px;
          font-size: 0.75em;
          pointer-events: none;
          animation: fadeOut 1s forwards;
        `;

        this.parentNode.style.position = 'relative';
        this.parentNode.appendChild(feedback);

        setTimeout(() => feedback.remove(), 1000);
      });
    });
  }

  // =====================================================
  // Table of Contents Progress
  // =====================================================

  /**
   * Add reading progress indicator to TOC
   */
  function initTocProgress() {
    const toc = document.querySelector('.md-nav--secondary');
    if (!toc) return;

    const headings = document.querySelectorAll('h2[id], h3[id]');
    if (headings.length === 0) return;

    function updateProgress() {
      const scrollPosition = window.scrollY;
      const documentHeight = document.documentElement.scrollHeight - window.innerHeight;
      const progress = Math.min(100, (scrollPosition / documentHeight) * 100);

      // Update progress bar if exists
      let progressBar = document.querySelector('.toc-progress');
      if (!progressBar) {
        progressBar = document.createElement('div');
        progressBar.className = 'toc-progress';
        progressBar.style.cssText = `
          height: 3px;
          background: var(--md-primary-fg-color);
          transition: width 0.2s;
          margin-bottom: 1em;
        `;
        toc.insertBefore(progressBar, toc.firstChild);
      }
      progressBar.style.width = `${progress}%`;

      // Highlight current section
      headings.forEach((heading, index) => {
        const rect = heading.getBoundingClientRect();
        const link = toc.querySelector(`a[href="#${heading.id}"]`);

        if (link) {
          if (rect.top >= 0 && rect.top <= 150) {
            link.classList.add('md-nav__link--active');
          } else {
            link.classList.remove('md-nav__link--active');
          }
        }
      });
    }

    window.addEventListener('scroll', updateProgress, { passive: true });
    updateProgress();
  }

  // =====================================================
  // Version Warning Banner
  // =====================================================

  /**
   * Show warning for development/unstable versions
   */
  function initVersionWarning() {
    const currentPath = window.location.pathname;

    if (currentPath.includes('/latest/') || currentPath.includes('/dev/')) {
      const existingBanner = document.querySelector('.version-warning');
      if (existingBanner) return;

      const banner = document.createElement('div');
      banner.className = 'version-warning';
      banner.innerHTML = `
        <div style="
          background: #ff9800;
          color: white;
          padding: 0.75em 1em;
          text-align: center;
          font-size: 0.9em;
        ">
          <strong>Warning:</strong> You are viewing documentation for a development version.
          <a href="/stable/" style="color: white; text-decoration: underline;">Switch to stable</a>
        </div>
      `;

      document.body.insertBefore(banner, document.body.firstChild);
    }
  }

  // =====================================================
  // Keyboard Navigation
  // =====================================================

  /**
   * Add keyboard shortcuts
   */
  function initKeyboardShortcuts() {
    document.addEventListener('keydown', function(e) {
      // Only when not in input field
      if (document.activeElement.tagName === 'INPUT' ||
          document.activeElement.tagName === 'TEXTAREA') {
        return;
      }

      // '/' to focus search
      if (e.key === '/') {
        e.preventDefault();
        const searchInput = document.querySelector('.md-search__input');
        if (searchInput) searchInput.focus();
      }

      // 'g' then 'h' to go home
      if (e.key === 'h' && window._lastKey === 'g') {
        window.location.href = '/';
      }

      // 'g' then 't' to go to tutorials
      if (e.key === 't' && window._lastKey === 'g') {
        window.location.href = '/tutorials/';
      }

      // 'g' then 'a' to go to API reference
      if (e.key === 'a' && window._lastKey === 'g') {
        window.location.href = '/api-reference/';
      }

      window._lastKey = e.key;
      setTimeout(() => { window._lastKey = null; }, 1000);
    });
  }

  // =====================================================
  // External Link Handling
  // =====================================================

  /**
   * Add external link indicator and open in new tab
   */
  function initExternalLinks() {
    document.querySelectorAll('a[href^="http"]').forEach(link => {
      // Skip internal links
      if (link.href.includes(window.location.hostname)) return;

      // Add external indicator
      if (!link.querySelector('.external-icon')) {
        link.setAttribute('target', '_blank');
        link.setAttribute('rel', 'noopener noreferrer');

        const icon = document.createElement('span');
        icon.className = 'external-icon';
        icon.innerHTML = ' ↗';
        icon.style.fontSize = '0.75em';
        link.appendChild(icon);
      }
    });
  }

  // =====================================================
  // Feedback Widget
  // =====================================================

  /**
   * Initialize page feedback collection
   */
  function initFeedbackWidget() {
    const feedbackContainer = document.querySelector('[data-md-component="feedback"]');
    if (!feedbackContainer) return;

    feedbackContainer.addEventListener('click', function(e) {
      if (e.target.matches('[data-md-value]')) {
        const value = e.target.getAttribute('data-md-value');
        const page = window.location.pathname;

        // Track feedback (you can integrate with analytics here)
        console.log('Page feedback:', { page, value });

        // Show thank you message
        feedbackContainer.innerHTML = '<p>Thanks for your feedback!</p>';
      }
    });
  }

  // =====================================================
  // Code Block Language Labels
  // =====================================================

  /**
   * Add language labels to code blocks
   */
  function initCodeLanguageLabels() {
    document.querySelectorAll('pre > code').forEach(block => {
      const classes = block.className.split(' ');
      const langClass = classes.find(c => c.startsWith('language-'));

      if (langClass) {
        const lang = langClass.replace('language-', '').toUpperCase();

        // Skip if label already exists
        if (block.parentNode.querySelector('.code-lang-label')) return;

        const label = document.createElement('span');
        label.className = 'code-lang-label';
        label.textContent = lang;
        label.style.cssText = `
          position: absolute;
          top: 0.5em;
          right: 3em;
          font-size: 0.7em;
          font-weight: 600;
          color: var(--md-default-fg-color--light);
          text-transform: uppercase;
          letter-spacing: 0.05em;
        `;

        block.parentNode.style.position = 'relative';
        block.parentNode.appendChild(label);
      }
    });
  }

  // =====================================================
  // Scroll to Top Button
  // =====================================================

  /**
   * Show scroll to top button on long pages
   */
  function initScrollToTop() {
    const button = document.createElement('button');
    button.className = 'scroll-to-top';
    button.innerHTML = '↑';
    button.setAttribute('aria-label', 'Scroll to top');
    button.style.cssText = `
      position: fixed;
      bottom: 2em;
      right: 2em;
      width: 3em;
      height: 3em;
      border-radius: 50%;
      border: none;
      background: var(--md-primary-fg-color);
      color: white;
      font-size: 1.5em;
      cursor: pointer;
      opacity: 0;
      transition: opacity 0.3s, transform 0.3s;
      z-index: 1000;
      display: flex;
      align-items: center;
      justify-content: center;
    `;

    document.body.appendChild(button);

    window.addEventListener('scroll', function() {
      if (window.scrollY > 300) {
        button.style.opacity = '1';
        button.style.transform = 'scale(1)';
      } else {
        button.style.opacity = '0';
        button.style.transform = 'scale(0.5)';
      }
    }, { passive: true });

    button.addEventListener('click', function() {
      window.scrollTo({ top: 0, behavior: 'smooth' });
    });
  }

  // =====================================================
  // Initialization
  // =====================================================

  /**
   * Initialize all enhancements when DOM is ready
   */
  function init() {
    initFeatureSearch();
    initCopyFeedback();
    initTocProgress();
    initVersionWarning();
    initKeyboardShortcuts();
    initExternalLinks();
    initFeedbackWidget();
    initCodeLanguageLabels();
    initScrollToTop();

    console.log('JoyfulJay Documentation initialized');
  }

  // Run on DOM ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  // Re-run on navigation (for SPA-like behavior)
  document.addEventListener('DOMContentSwitch', init);

})();

// Add fade out animation for copy feedback
const style = document.createElement('style');
style.textContent = `
  @keyframes fadeOut {
    from { opacity: 1; transform: translateY(0); }
    to { opacity: 0; transform: translateY(-10px); }
  }
`;
document.head.appendChild(style);
