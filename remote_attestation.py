import hmac
import hashlib
import sys

# Configuration
firmware_file_path = "firmware.bin"  # Path to your firmware binary file
key_file_path = "private_key.bin"  # Path to the binary key file
chunk_size = 4096  # Same chunk size as used in the ESP32 script
challenge= b"test123"

if len(sys.argv) > 1:
    parameter = sys.argv[1]
    challenge = parameter.encode('utf-8')
else:
    print("No challenge provided provided.")
    quit()

def derive_final_hmac(firmware_hmac, key, challenge=None):
    hmac_calculator = hmac.new(key, digestmod=hashlib.sha256)
    hmac_calculator.update(firmware_hmac)
    hmac_calculator.update(challenge)
    final_result = hmac_calculator.digest()
    return final_result

def load_key_from_file(key_path):
    """Loads a binary key from a file."""
    try:
        with open(key_path, "rb") as key_file:
            key = key_file.read()
        print(f"Loaded key from {key_path}.")
        return key
    except FileNotFoundError:
        print(f"Error: Key file '{key_path}' not found.")
        return None
    except Exception as e:
        print(f"An error occurred while reading the key: {e}")
        return None

def calculate_combined_hmac(firmware_path, key, chunk_size, challenge):
    """
    Calculates the HMAC of a firmware binary file, combining previous results.
    """
    try:
        # Initialize the intermediate HMAC result
        intermediate_result = b'\x00' * 32

        # Open the firmware file
        with open(firmware_path, "rb") as firmware_file:
            chunk_count = 0

            while True:
                # Read a chunk of the firmware
                chunk = firmware_file.read(chunk_size)
                if not chunk:  # End of file
                    break

                # Combine the previous HMAC with the current chunk
                hmac_calculator = hmac.new(key, digestmod=hashlib.sha256)
                hmac_calculator.update(intermediate_result)
                hmac_calculator.update(chunk)
                hmac_calculator.update(challenge)

                # Update the intermediate result
                intermediate_result = hmac_calculator.digest()

                print(f"Chunk {chunk_count}: HMAC = {hmac_calculator.hexdigest()}")
                chunk_count += 1

        # Final HMAC result
        return intermediate_result.hex()

    except FileNotFoundError:
        print(f"Error: Firmware file '{firmware_path}' not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

# Load the key from the file
hmac_key = load_key_from_file(key_file_path)

if hmac_key:
    # Calculate and display the final HMAC
    final_hmac = calculate_combined_hmac(firmware_file_path, hmac_key, chunk_size, challenge)
    if final_hmac:
        print(f"Final Firmware HMAC: {final_hmac}")
