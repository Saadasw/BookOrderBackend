# Initialize
from otp import Infobip2FA
import os
API_KEY = os.getenv("API_KEY")

client = Infobip2FA(API_KEY)

# Create app and template
app_id = client.get_or_create_application("My_App")
client.create_message_template("login", "Your code is {{pin}}")

# Send PIN
result = client.send_pin("+8801752304601", template_name="login")
print(result)
# User enters received PIN
user_pin = input("Enter PIN: ")
print(user_pin)
# Verify
verified = client.verify_pin(result["pinId"], user_pin)


print(verified)