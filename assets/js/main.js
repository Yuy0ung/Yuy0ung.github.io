document.addEventListener('DOMContentLoaded', () => {
  console.log('Yuque Pro: JS Loaded');

  // Theme Toggle
  const themeCheckbox = document.getElementById('checkbox');
  const html = document.documentElement;
  
  // Sync checkbox with current theme (theme is already applied in head)
  const currentTheme = html.getAttribute('data-theme');
  if (currentTheme === 'dark' && themeCheckbox) {
    themeCheckbox.checked = true;
  }

  if (themeCheckbox) {
    themeCheckbox.addEventListener('change', () => {
      const newTheme = themeCheckbox.checked ? 'dark' : 'light';
      html.setAttribute('data-theme', newTheme);
      localStorage.setItem('theme', newTheme);
      console.log('Theme changed to:', newTheme);
    });
  }

  // Tree Toggle (Event Delegation)
  document.addEventListener('click', (e) => {
    // Prevent duplicate handling (HMR or duplicate listeners)
    if (e.treeToggleHandled) return;
    
    // 1. Identify the trigger
    const toggleBtn = e.target.closest('.tree-toggle');
    const sectionLink = e.target.closest('.section-link');
    const trigger = toggleBtn || sectionLink;
    
    if (!trigger) return;
    
    console.log('Tree toggle triggered by:', trigger);

    // 2. Identify the container (li)
    const li = trigger.closest('li');
    if (!li) {
        console.log('No parent li found');
        return;
    }
    
    // Mark event as handled ONLY after we confirm it's a relevant click
    e.treeToggleHandled = true;
    
    // 3. Find the controlled elements within this li
    // Use direct child traversal to avoid selecting nested elements
    let children = null;
    let toggleIcon = null;

    for (let i = 0; i < li.children.length; i++) {
        const child = li.children[i];
        if (child.classList.contains('tree-children')) {
            children = child;
        }
        if (child.classList.contains('tree-toggle')) {
            toggleIcon = child;
        }
    }
    
    if (!children || !toggleIcon) {
        console.log('Missing children or toggleIcon (direct check)', { children, toggleIcon });
        // Fallback: Try querySelector but only if it's strictly the direct parent
        if (!children) {
             const found = li.querySelector('.tree-children');
             if (found && found.parentElement === li) children = found;
        }
        if (!toggleIcon) {
             const found = li.querySelector('.tree-toggle');
             if (found && found.parentElement === li) toggleIcon = found;
        }
        
        if (!children || !toggleIcon) {
             console.log('Still missing children or toggleIcon after fallback');
             return;
        }
    }
    
    console.log('Toggling tree section');

    // 5. Action
    e.preventDefault();
    e.stopPropagation();
    
    if (children.classList.contains('hidden')) {
        console.log('Opening section');
        children.classList.remove('hidden');
        children.style.display = 'block'; // Force display
        toggleIcon.classList.remove('collapsed');
        toggleIcon.classList.add('expanded');
    } else {
        console.log('Closing section');
        children.classList.add('hidden');
        children.style.display = 'none'; // Force hide
        toggleIcon.classList.remove('expanded');
        toggleIcon.classList.add('collapsed');
    }
  });

  // Highlight Active Link
  const currentUrl = window.location.pathname;
  console.log('Current URL:', currentUrl);
  
  const links = document.querySelectorAll('.tree a');
  links.forEach(link => {
    // Simple normalization
    const linkHref = link.getAttribute('href');
    if (linkHref && (linkHref === currentUrl || linkHref.replace(/\/$/, '') === currentUrl.replace(/\/$/, ''))) {
      link.style.fontWeight = 'bold';
      link.style.color = 'var(--link-color)';
      // Expand parents
      let parent = link.closest('.tree-children');
      while (parent) {
        parent.classList.remove('hidden');
        parent.style.display = 'block'; // Ensure parent is visible
        const toggle = parent.parentElement.querySelector('.tree-toggle');
        if (toggle) {
          toggle.classList.remove('collapsed');
          toggle.classList.add('expanded');
        }
        parent = parent.parentElement.closest('.tree-children');
      }
    }
  });

  // Hover Preview
  const tooltip = document.createElement('div');
  tooltip.className = 'preview-tooltip';
  document.body.appendChild(tooltip);

  let hoverTimeout;
  // Only enable preview on homepage center content, not sidebars
  const articleLinks = document.querySelectorAll('.homepage-tree .article-link');

  articleLinks.forEach(link => {
    link.addEventListener('mouseenter', (e) => {
      // Disable on mobile (narrow viewport)
      if (window.innerWidth <= 768) return;

      const summary = link.getAttribute('data-summary');
      if (!summary) return;

      // Capture initial mouse position
      const initialX = e.clientX;
      const initialY = e.clientY;

      hoverTimeout = setTimeout(() => {
        // Limit summary length
        const truncatedSummary = summary.length > 200 ? summary.substring(0, 200) + '...' : summary;
        tooltip.textContent = truncatedSummary;
        tooltip.style.display = 'block';
        
        // Position tooltip based on mouse coordinates (fixed position)
        // Add a small offset so cursor doesn't cover text
        let left = initialX + 15;
        let top = initialY + 15;

        // Boundary check: prevent going off-screen
        const tooltipWidth = 500; // Approximate max width
        if (left + tooltipWidth > window.innerWidth) {
            left = initialX - tooltipWidth - 15; // Show to the left if space is tight
        }
        
        // Ensure it doesn't go below screen
        // We can't easily know height before render, but we can guess or use bottom alignment
        if (top + 150 > window.innerHeight) {
             top = initialY - 140; // Flip up
        }
        
        tooltip.style.left = `${left}px`;
        tooltip.style.top = `${top}px`;
        // Ensure tooltip uses fixed positioning relative to viewport
        tooltip.style.position = 'fixed';
      }, 500);
    });

    link.addEventListener('mouseleave', () => {
      clearTimeout(hoverTimeout);
      tooltip.style.display = 'none';
    });
  });

  // Code Block Enhancements (Copy Button & Wrapper)
  const codeBlocks = document.querySelectorAll('pre');
  codeBlocks.forEach(block => {
    // Avoid double processing
    if (block.closest('.code-wrapper')) return;

    // Create wrapper
    const wrapper = document.createElement('div');
    wrapper.className = 'code-wrapper';
    
    // Insert wrapper before block
    block.parentNode.insertBefore(wrapper, block);
    
    // Move block into wrapper
    wrapper.appendChild(block);
    
    // Create copy button
    const copyBtn = document.createElement('button');
    copyBtn.className = 'copy-btn';
    copyBtn.textContent = 'Copy';
    
    copyBtn.addEventListener('click', () => {
      const code = block.querySelector('code');
      const text = code ? code.innerText : block.innerText;
      
      navigator.clipboard.writeText(text).then(() => {
        copyBtn.textContent = 'Copied!';
        setTimeout(() => {
          copyBtn.textContent = 'Copy';
        }, 2000);
      }).catch(err => {
        console.error('Failed to copy:', err);
        copyBtn.textContent = 'Error';
      });
    });
    
    wrapper.appendChild(copyBtn);
  });

  // Title & Date Fix
  const article = document.querySelector('.markdown-body');
  if (article) {
    const templateTitle = document.querySelector('.post-title-template');
    const postDate = document.querySelector('.post-date');
    const firstH1 = article.querySelector('h1');

    if (firstH1) {
      // Content has a title (H1)
      // Hide the template title to avoid duplication
      if (templateTitle) {
        templateTitle.style.display = 'none';
      }
      
      // Move date after the content's first H1
      if (postDate) {
        firstH1.after(postDate);
      }
    }
  }

  // TOC ScrollSpy & Auto-scroll
  const tocLinks = document.querySelectorAll('#TableOfContents a');
  const headers = Array.from(tocLinks).map(link => {
    const id = link.getAttribute('href').slice(1);
    return document.getElementById(id);
  }).filter(header => header !== null);

  if (headers.length > 0) {
    // 1. Highlight Logic (IntersectionObserver)
    const observerCallback = (entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          // Remove active class from all
          tocLinks.forEach(link => link.classList.remove('active'));
          
          // Add to current
          const id = entry.target.id;
          const activeLink = document.querySelector(`#TableOfContents a[href="#${id}"]`);
          if (activeLink) {
            activeLink.classList.add('active');
            
            // 2. Auto-scroll Logic
            // Check if active link is out of view in the sidebar
            const sidebar = document.querySelector('.sidebar-right');
            if (sidebar) {
              const linkRect = activeLink.getBoundingClientRect();
              const sidebarRect = sidebar.getBoundingClientRect();
              
              // If link is above visible area or below visible area
              const relativeTop = linkRect.top - sidebarRect.top;
              const relativeBottom = linkRect.bottom - sidebarRect.top;
              
              if (relativeTop < 0 || relativeBottom > sidebar.clientHeight) {
                // Scroll to center the link
                sidebar.scrollTo({
                  top: activeLink.offsetTop - sidebar.clientHeight / 2 + activeLink.clientHeight / 2,
                  behavior: 'smooth'
                });
              }
            }
          }
        }
      });
    };

    const observerOptions = {
      root: null,
      // Adjust rootMargin to trigger when header is near top of viewport
      // -100px from top means it triggers when it passes that line
      rootMargin: '0px 0px -80% 0px', 
      threshold: 0
    };

    const observer = new IntersectionObserver(observerCallback, observerOptions);
    headers.forEach(header => observer.observe(header));
  }

  // Search Functionality
  const searchTrigger = document.getElementById('search-trigger');
  const searchModal = document.getElementById('search-modal');
  const searchInput = document.getElementById('search-input');
  const searchResults = document.getElementById('search-results');
  const searchLoading = document.querySelector('.search-loading');
  let searchIndex = null;
  let selectedIndex = -1;

  // Open Modal
  const openSearch = (e) => {
    // Set transform origin based on click position
    const modalContent = document.querySelector('.search-modal-content');
    
    if (e && e.type === 'click' && e.currentTarget) {
      const triggerRect = e.currentTarget.getBoundingClientRect();
      const triggerX = triggerRect.left + triggerRect.width / 2;
      const triggerY = triggerRect.top + triggerRect.height / 2;
      
      // Calculate modal position (it's centered horizontally, and 15vh from top)
      // We need to approximate or calculate where the modal content will be.
      // Since it's fixed 600px width (max 90%) and centered:
      const windowWidth = window.innerWidth;
      const modalWidth = Math.min(600, windowWidth * 0.9);
      const modalLeft = (windowWidth - modalWidth) / 2;
      const modalTop = window.innerHeight * 0.15; // 15vh padding top
      
      const originX = triggerX - modalLeft;
      const originY = triggerY - modalTop;
      
      modalContent.style.transformOrigin = `${originX}px ${originY}px`;
    } else {
      // Default to center top if opened via shortcut or other means
      modalContent.style.transformOrigin = 'center top';
    }

    searchModal.classList.add('open');
    searchInput.focus();
    if (!searchIndex) {
      loadSearchIndex();
    }
  };

  // Close Modal
  const closeSearch = () => {
    // Add closing class to trigger animation
    searchModal.classList.add('closing');
    searchModal.classList.remove('open');
    
    // Wait for animation to finish before hiding completely and resetting
    setTimeout(() => {
      searchModal.classList.remove('closing');
      searchInput.value = '';
      searchResults.innerHTML = '';
      selectedIndex = -1;
    }, 200); // Match animation duration (0.2s)
  };

  if (searchTrigger) {
    searchTrigger.addEventListener('click', openSearch);
  }

  const mobileSearchTrigger = document.getElementById('mobile-search-trigger');
  if (mobileSearchTrigger) {
    mobileSearchTrigger.addEventListener('click', openSearch);
  }

  // Mobile Search & Exit Buttons
  const mobileExitBtn = document.getElementById('mobile-exit-btn');
  const mobileSearchBtn = document.getElementById('mobile-search-btn');

  if (mobileExitBtn) {
    mobileExitBtn.addEventListener('click', closeSearch);
  }

  if (mobileSearchBtn) {
    mobileSearchBtn.addEventListener('click', () => {
      // Trigger search explicitly (for safety) and hide keyboard
      const event = new Event('input', { bubbles: true });
      searchInput.dispatchEvent(event);
      searchInput.blur();
    });
  }

  // Escape to close
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && searchModal.classList.contains('open')) {
      closeSearch();
    }
  });

  // Click outside to close
  searchModal.addEventListener('click', (e) => {
    if (e.target === searchModal) {
      closeSearch();
    }
  });

  // Load Index
  const loadSearchIndex = async () => {
    searchLoading.style.display = 'block';
    try {
      const response = await fetch('/index.json?t=' + new Date().getTime());
      searchIndex = await response.json();
      console.log('Search index loaded, items:', searchIndex ? searchIndex.length : 0);
    } catch (error) {
      console.error('Failed to load search index:', error);
      searchResults.innerHTML = '<div style="padding:20px;text-align:center;">Failed to load search index.</div>';
    } finally {
      searchLoading.style.display = 'none';
    }
  };

  // Search Logic
  searchInput.addEventListener('input', (e) => {
    const query = e.target.value.toLowerCase().trim();
    if (!query) {
      searchResults.innerHTML = '';
      selectedIndex = -1;
      return;
    }

    if (!searchIndex) return;

    // Simple filter
    const results = searchIndex.filter(item => {
      const titleMatch = item.title && item.title.toLowerCase().includes(query);
      const contentMatch = item.content && item.content.toLowerCase().includes(query);
      return titleMatch || contentMatch;
    }).slice(0, 50); // Limit to 50 results

    renderResults(results);
  });

  // Render Results
  const renderResults = (results) => {
    if (results.length === 0) {
      searchResults.innerHTML = '<div style="padding:20px;text-align:center;color:var(--text-color);opacity:0.6;">No results found.</div>';
      return;
    }

    let html = '';
    results.forEach((item, index) => {
      html += `
        <div class="search-result-item" data-index="${index}" onclick="window.location.href='${item.link}'">
          <span class="search-result-title">${item.title}</span>
          <span class="search-result-excerpt">${item.summary || 'No summary available.'}</span>
        </div>
      `;
    });
    searchResults.innerHTML = html;
    selectedIndex = -1;
  };

  // Keyboard Navigation in Results
  searchInput.addEventListener('keydown', (e) => {
    const items = document.querySelectorAll('.search-result-item');
    if (items.length === 0) return;

    if (e.key === 'ArrowDown') {
      e.preventDefault();
      selectedIndex = (selectedIndex + 1) % items.length;
      updateSelection(items);
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      selectedIndex = (selectedIndex - 1 + items.length) % items.length;
      updateSelection(items);
    } else if (e.key === 'Enter') {
      e.preventDefault();
      if (selectedIndex >= 0) {
        items[selectedIndex].click();
      } else if (items.length > 0) {
        // Default to first if none selected
        items[0].click();
      }
    }
  });

  const updateSelection = (items) => {
    items.forEach((item, index) => {
      if (index === selectedIndex) {
        item.classList.add('selected');
        item.scrollIntoView({ block: 'nearest' });
      } else {
        item.classList.remove('selected');
      }
    });
  };

});
