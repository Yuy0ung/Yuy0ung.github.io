import os

CONTENT_DIR = 'content'
TARGET_DATE = '2025-12-11T00:00:00+08:00'

def add_front_matter():
    count = 0
    for root, dirs, files in os.walk(CONTENT_DIR):
        for file in files:
            if file.endswith('.md'):
                file_path = os.path.join(root, file)
                
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                except UnicodeDecodeError:
                    print(f"Skipping {file_path} due to encoding issue")
                    continue
                
                # Check if it likely already has front matter
                # We check if it starts with --- followed by a newline or strictly just ---
                if content.startswith('---\n') or content.startswith('---\r\n'):
                    continue
                
                # Prepare front matter
                title = os.path.splitext(file)[0]
                
                front_matter = f"""---
title: "{title}"
date: {TARGET_DATE}
draft: false
---

"""
                new_content = front_matter + content
                
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(new_content)
                
                print(f"Added front matter to: {file_path}")
                count += 1
    
    print(f"Total files updated: {count}")

if __name__ == '__main__':
    add_front_matter()
