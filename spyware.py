import os
import random
import shutil

# Set the directory for creating custom files
custom_files_directory = 'custom_files'
os.makedirs(custom_files_directory, exist_ok=True)

def create_spyware_file(file_path):
    # Create a custom spyware-like file
    with open(file_path, 'wb') as file:
        # Customize spyware-like content based on your features
        # Example: Use feature values or patterns relevant to your spyware characteristics
        file.write(b'\x01\x02\x03' * 100)  # Replace with actual content

def create_benign_file(file_path):
    # Create a custom benign file
    with open(file_path, 'wb') as file:
        # Customize benign content based on your features
        # Example: Use feature values or patterns relevant to benign characteristics
        file.write(b'\x00\xff\x00\xff' * 100)  # Replace with actual content

def generate_custom_files(num_samples=10):
    for i in range(num_samples):
        # Randomly choose whether to create a spyware or benign file
        is_spyware = random.choice([True, False])

        # Create a unique file name
        file_name = f"custom_file_{i}.exe"
        file_path = os.path.join(custom_files_directory, file_name)

        # Call the appropriate function to create the file
        if is_spyware:
            create_spyware_file(file_path)
        else:
            create_benign_file(file_path)

if __name__ == "__main__":
    # Generate custom files
    generate_custom_files()

    # Optional: Zip the custom files directory for easier sharing
    shutil.make_archive('custom_files_archive', 'zip', custom_files_directory)
