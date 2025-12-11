document.addEventListener('DOMContentLoaded', () => {
  // Theme Toggle
  const themeToggle = document.getElementById('theme-toggle');
  const body = document.body;
  const savedTheme = localStorage.getItem('theme');
  const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;

  function updateIcon() {
    // Optional: Toggle icon visibility if needed, currently CSS handles colors
  }

  if (savedTheme === 'dark' || (!savedTheme && prefersDark)) {
    body.classList.add('dark-mode');
    body.classList.remove('light-mode');
  } else {
    body.classList.add('light-mode');
    body.classList.remove('dark-mode');
  }

  themeToggle.addEventListener('click', () => {
    if (body.classList.contains('dark-mode')) {
      body.classList.replace('dark-mode', 'light-mode');
      localStorage.setItem('theme', 'light');
    } else {
      body.classList.replace('light-mode', 'dark-mode');
      localStorage.setItem('theme', 'dark');
    }
  });

  // Hover Preview
  const previewBox = document.getElementById('hover-preview');
  let hoverTimer;

  document.querySelectorAll('.tree-view a[data-summary]').forEach(link => {
    link.addEventListener('mouseenter', (e) => {
      const summary = link.getAttribute('data-summary');
      if (!summary) return;

      hoverTimer = setTimeout(() => {
        previewBox.textContent = summary;
        previewBox.classList.remove('hidden');
        
        // Position
        const rect = link.getBoundingClientRect();
        let top = rect.top;
        let left = rect.right + 10;
        
        // Check bounds
        if (top + previewBox.offsetHeight > window.innerHeight) {
          top = window.innerHeight - previewBox.offsetHeight - 10;
        }
        
        previewBox.style.top = `${top}px`;
        previewBox.style.left = `${left}px`;
      }, 1000); // 1 second delay
    });

    link.addEventListener('mouseleave', () => {
      clearTimeout(hoverTimer);
      previewBox.classList.add('hidden');
    });
  });
});
