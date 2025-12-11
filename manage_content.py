import os

CONTENT_DIR = '/Users/yuy0ung/Desktop/yuque-pro/content'
TARGET_DATE = '2025-12-11T00:00:00+08:00'

def process_content():
    print(f"Scanning directory: {CONTENT_DIR}")
    
    # Walk through the directory structure
    for root, dirs, files in os.walk(CONTENT_DIR):
        # 1. Check/Create _index.md for the current directory
        # Skip the root content folder itself if preferred, but usually harmless to check
        if root != CONTENT_DIR:
            index_path = os.path.join(root, '_index.md')
            if not os.path.exists(index_path):
                dir_name = os.path.basename(root)
                content = f"""---
title: "{dir_name}"
date: {TARGET_DATE}
draft: false
---
"""
                try:
                    with open(index_path, 'w', encoding='utf-8') as f:
                        f.write(content)
                    print(f"Created section index: {index_path}")
                except Exception as e:
                    print(f"Error creating {index_path}: {e}")

        # 2. Process .md files in the current directory
        for file in files:
            # Skip _index.md files for front matter addition (they are handled above or manually)
            if file.endswith('.md') and file != '_index.md':
                file_path = os.path.join(root, file)
                
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                except UnicodeDecodeError:
                    print(f"Skipping {file_path} due to encoding issue")
                    continue
                
                # Check if it already has front matter
                # A simple check: does it start with ---?
                if content.lstrip().startswith('---'):
                    continue
                
                # Prepare front matter
                # Use filename as title, removing extension
                title = os.path.splitext(file)[0]
                
                front_matter = f"""---
title: "{title}"
date: {TARGET_DATE}
draft: false
---

"""
                new_content = front_matter + content
                
                try:
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(new_content)
                    print(f"Added front matter to: {file_path}")
                except Exception as e:
                    print(f"Error updating {file_path}: {e}")

if __name__ == '__main__':
    process_content()
