(() => {
  // <stdin>
  document.addEventListener("DOMContentLoaded", () => {
    console.log("Yuque Pro: JS Loaded");
    const themeToggleBtn = document.getElementById("theme-toggle");
    const html = document.documentElement;
    const savedTheme = localStorage.getItem("theme");
    if (savedTheme) {
      html.setAttribute("data-theme", savedTheme);
    } else if (window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches) {
      html.setAttribute("data-theme", "dark");
    }
    if (themeToggleBtn) {
      themeToggleBtn.addEventListener("click", () => {
        const currentTheme = html.getAttribute("data-theme");
        const newTheme = currentTheme === "dark" ? "light" : "dark";
        html.setAttribute("data-theme", newTheme);
        localStorage.setItem("theme", newTheme);
        console.log("Theme changed to:", newTheme);
      });
    }
    const toggles = document.querySelectorAll(".tree-toggle");
    toggles.forEach((toggle) => {
      toggle.addEventListener("click", (e) => {
        e.preventDefault();
        e.stopPropagation();
        const parent = toggle.parentElement;
        const children = parent.querySelector(".tree-children");
        if (children) {
          children.classList.toggle("hidden");
          toggle.classList.toggle("collapsed");
          toggle.classList.toggle("expanded");
        }
      });
    });
    const currentUrl = window.location.pathname;
    console.log("Current URL:", currentUrl);
    const links = document.querySelectorAll(".tree a");
    links.forEach((link) => {
      const linkHref = link.getAttribute("href");
      if (linkHref && (linkHref === currentUrl || linkHref.replace(/\/$/, "") === currentUrl.replace(/\/$/, ""))) {
        link.style.fontWeight = "bold";
        link.style.color = "var(--link-color)";
        let parent = link.closest(".tree-children");
        while (parent) {
          parent.classList.remove("hidden");
          const toggle = parent.parentElement.querySelector(".tree-toggle");
          if (toggle) {
            toggle.classList.remove("collapsed");
            toggle.classList.add("expanded");
          }
          parent = parent.parentElement.closest(".tree-children");
        }
      }
    });
    const tooltip = document.createElement("div");
    tooltip.className = "preview-tooltip";
    document.body.appendChild(tooltip);
    let hoverTimeout;
    const articleLinks = document.querySelectorAll(".article-link");
    articleLinks.forEach((link) => {
      link.addEventListener("mouseenter", (e) => {
        const summary = link.getAttribute("data-summary");
        if (!summary) return;
        hoverTimeout = setTimeout(() => {
          const truncatedSummary = summary.length > 200 ? summary.substring(0, 200) + "..." : summary;
          tooltip.textContent = truncatedSummary;
          tooltip.style.display = "block";
          const rect = link.getBoundingClientRect();
          let left = rect.right + 10;
          if (left + 300 > window.innerWidth) {
            left = rect.left - 310;
          }
          tooltip.style.left = `${left}px`;
          tooltip.style.top = `${rect.top}px`;
        }, 1e3);
      });
      link.addEventListener("mouseleave", () => {
        clearTimeout(hoverTimeout);
        tooltip.style.display = "none";
      });
    });
  });
})();
