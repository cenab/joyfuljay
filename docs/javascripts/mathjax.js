/**
 * MathJax Configuration for JoyfulJay Documentation
 * Used for rendering mathematical formulas in feature documentation
 */

window.MathJax = {
  tex: {
    inlineMath: [['$', '$'], ['\\(', '\\)']],
    displayMath: [['$$', '$$'], ['\\[', '\\]']],
    processEscapes: true,
    processEnvironments: true,
    packages: ['base', 'ams', 'newcommand', 'autoload'],
    macros: {
      // Common macros for network traffic analysis
      IAT: '\\text{IAT}',
      RTT: '\\text{RTT}',
      MSS: '\\text{MSS}',
      MTU: '\\text{MTU}',

      // Statistical notation
      E: '\\mathbb{E}',
      Var: '\\text{Var}',
      Std: '\\text{Std}',

      // Set notation
      R: '\\mathbb{R}',
      N: '\\mathbb{N}',

      // Custom operators
      argmax: '\\operatorname*{argmax}',
      argmin: '\\operatorname*{argmin}'
    }
  },
  options: {
    ignoreHtmlClass: 'tex2jax_ignore',
    processHtmlClass: 'tex2jax_process',
    renderActions: {
      findScript: [10, function (doc) {
        for (const node of document.querySelectorAll('script[type^="math/tex"]')) {
          const display = !!node.type.match(/; *mode=display/);
          const math = new doc.options.MathItem(node.textContent, doc.inputJax[0], display);
          const text = document.createTextNode('');
          node.parentNode.replaceChild(text, node);
          math.start = {node: text, delim: '', n: 0};
          math.end = {node: text, delim: '', n: 0};
          doc.math.push(math);
        }
      }, '']
    }
  },
  loader: {
    load: ['[tex]/ams', '[tex]/newcommand', '[tex]/autoload']
  }
};

// Initialize MathJax after it loads
document$.subscribe(() => {
  if (typeof MathJax !== 'undefined') {
    MathJax.typesetPromise()
      .then(() => {
        console.log('MathJax typeset complete');
      })
      .catch((err) => {
        console.error('MathJax typeset error:', err);
      });
  }
});
