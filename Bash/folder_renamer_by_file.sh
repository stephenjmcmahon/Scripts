#!/bin/bash

# IMPORTANT: Don't forget to give the script "execute" permission by running 'chmod +x folder_renamer_by_file.sh'

# Script to rename folders based on a file name inside each folder
# Run this script from the parent directory containing the subfolders

# Prompt the user for a filename pattern (e.g., *.mp4, *.txt, example_file.ext)
read -p "Enter the filename pattern to search for (e.g., '*.mp4', 'example.txt'): " file_pattern

# Check if user input is empty
if [ -z "$file_pattern" ]; then
    echo "Error: Filename pattern cannot be empty. Exiting..."
    exit 1
fi

# Loop through all subdirectories
for folder in */; do
    # Check if it is a directory
    if [ -d "$folder" ]; then
        echo "Processing folder: $folder"

        # Find the first file matching the pattern inside the folder
        target_file=$(find "$folder" -maxdepth 1 -type f -name "$file_pattern" | head -n 1)

        # If no file matches the pattern, skip to the next folder
        if [ -z "$target_file" ]; then
            echo "No file matching '$file_pattern' found in $folder. Skipping..."
            continue
        fi

        # Extract the filename (without the extension)
        file_basename=$(basename "$target_file")
        file_name_no_ext="${file_basename%.*}"

        # Sanitize the filename to make it safe for use as a folder name
        sanitized_filename=$(echo "$file_name_no_ext" | tr '/\\:*?"<>|' '_')

        # Remove trailing slashes in folder names
        clean_folder=${folder%/}

        # Rename the folder
        if [ "$clean_folder" != "$sanitized_filename" ]; then
            mv "$clean_folder" "$sanitized_filename"
            echo "Renamed folder '$clean_folder' to '$sanitized_filename'."
        else
            echo "Folder '$clean_folder' already matches the file name."
        fi
    fi
done

echo "Done!"
