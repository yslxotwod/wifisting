#!/bin/bash
# png2svg.sh - Convert PNG icons to SVG with currentColor for CSS styling

if [ -z "$1" ]; then
    echo "Usage: $0 <directory_with_pngs>"
    exit 1
fi

DIR="$1"
cd "$DIR" || exit 1

for file in *.png; do
    [ -e "$file" ] || continue
    base="${file%.*}"
    
    echo "Processing $file..."
    
    # 1. Preprocess and trace
    convert "$file" -colorspace Gray -threshold 50% "$base.pbm"
    potrace "$base.pbm" -s -o "$base.svg"
    
    # 2. Replace hardcoded colors with currentColor
    sed -i 's/fill="#[0-9a-fA-F]\{6\}"/fill="currentColor"/g; s/fill="black"/fill="currentColor"/g; s/stroke="#[0-9a-fA-F]\{6\}"/stroke="currentColor"/g; s/stroke="black"/stroke="currentColor"/g' "$base.svg"
    
    # 3. Clean up temp file
    rm "$base.pbm"
    
    echo "✅ Created $base.svg"
done