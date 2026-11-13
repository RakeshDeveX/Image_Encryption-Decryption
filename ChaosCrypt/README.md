# ChaosCrypt — Image Encryption Desktop Software

A Python desktop application for image encryption/decryption with image previews and basic statistical analysis.

## Important security note

- **AES-256-GCM is the recommended mode.** It is authenticated encryption: a wrong password or modified ciphertext is rejected.
- **Chaotic (paper demo) is for academic demonstration only.** It follows the paper-inspired logistic-map / permutation / AES-S-box / XOR workflow, but it is not suitable for protecting real secrets. The included fixed-key sensitivity test shows that changing one plaintext byte changes only one ciphertext byte in this implementation. Do not describe this mode as secure or as a verified exact reproduction of every paper detail.
- Save encrypted images as **PNG only**. JPEG recompression changes pixel bytes and will prevent decryption.
- Keep a backup of the original image and remember the password. There is no password recovery.

## 1. Requirements

- Windows 10/11 (or another OS with Python and Tk support)
- Python 3.10 or newer recommended
- Internet connection only for installing packages

## 2. Setup on Windows

1. Extract `ChaosCrypt.zip` into a folder, for example `C:\\Users\\YourName\\Desktop\\ChaosCrypt`.
2. Open that folder in File Explorer.
3. Click the address bar, type `cmd`, and press Enter.
4. Create a virtual environment:

   ```bat
   py -m venv .venv
   ```

5. Activate it:

   ```bat
   .venv\\Scripts\\activate
   ```

6. Upgrade pip and install requirements:

   ```bat
   python -m pip install --upgrade pip
   pip install -r requirements.txt
   ```

## 3. Run the software

```bat
python app.py
```

## 4. Encrypt an image

1. Select **AES-256-GCM** in the Algorithm control.
2. Enter a strong password (at least 8 characters; a longer unique passphrase is better).
3. Click **Open image...** and choose a PNG, JPG, JPEG, BMP, TIFF, or WEBP image.
4. Click **Encrypt** and wait for the completion message.
5. Click **Save result as PNG...** and save the encrypted file. Do not convert it to JPEG or resize it.

## 5. Decrypt an image

1. Open the encrypted PNG created by this application.
2. Enter the same password used during encryption.
3. Click **Decrypt**.
4. After the success / integrity-check message, click **Save result as PNG...** to save the recovered image.

## 6. Research demonstration mode

Choose **Chaotic (paper)** only to demonstrate the paper-inspired steps and compare image statistics. It uses a logistic map, row/column permutation, AES S-box substitution, and XOR diffusion matrix. This implementation has a known diffusion weakness in the fixed-key test, so it must not be used for real security.

## 7. Run tests

```bat
python test_core.py
```

The tests cover AES S-box values, encrypt/decrypt round trips for grayscale/RGB/RGBA images, wrong-password rejection, PNG metadata round trips, GCM tamper detection, and a fixed-key sensitivity demonstration.

## Project files

- `app.py` — CustomTkinter desktop interface
- `imgcrypt_core.py` — image processing, encryption, decryption, PNG metadata, and metrics
- `test_core.py` — automated correctness and security-behavior tests
- `requirements.txt` — Python dependencies

## Research paper

Alghamdi, Y., Munir, A., and Ahmad, J. “A Lightweight Image Encryption Algorithm Based on Chaotic Map and Random Substitution.” *Entropy*, 2022, 24(10), 1344. DOI: https://doi.org/10.3390/e24101344

This project is an educational implementation inspired by the paper, alongside AES-256-GCM as the secure application mode. Do not claim that the experimental chaotic mode is a production-grade cryptographic algorithm.
