import http.client
import json
import os
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import time


class Infobip2FA:
    """A complete 2FA implementation using Infobip API"""
    
    def __init__(self, api_key: str, base_url: str = "2mel1m.api.infobip.com"):
        """
        Initialize the 2FA client
        
        Args:
            api_key: Your Infobip API key
            base_url: Infobip API base URL
        """
        self.api_key = api_key
        self.base_url = base_url
        self.application_id = None
        self.message_templates = {}
        
    def _make_request(self, method: str, path: str, payload: Optional[Dict] = None) -> Dict:
        """Make an HTTP request to Infobip API"""
        conn = http.client.HTTPSConnection(self.base_url)
        
        headers = {
            'Authorization': f'App {self.api_key}',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        
        body = json.dumps(payload) if payload else None
        
        try:
            conn.request(method, path, body, headers)
            response = conn.getresponse()
            data = response.read().decode('utf-8')
            
            if response.status >= 400:
                raise Exception(f"API Error {response.status}: {data}")
                
            return json.loads(data) if data else {}
            
        except Exception as e:
            print(f"Request failed: {e}")
            raise
        finally:
            conn.close()
    
    def create_application(self, name: str, config: Optional[Dict] = None) -> str:
        """
        Create a new 2FA application
        
        Args:
            name: Application name
            config: Optional configuration overrides
            
        Returns:
            Application ID
        """
        default_config = {
            "pinAttempts": 3,  # Reduced from 10 for better security
            "allowMultiplePinVerifications": False,  # More secure
            "pinTimeToLive": "10m",  # Reduced from 15m
            "verifyPinLimit": "1/3s",
            "sendPinPerApplicationLimit": "100/1d",
            "sendPinPerPhoneNumberLimit": "5/1d"  # Reduced from 10
        }
        
        if config:
            default_config.update(config)
        
        payload = {
            "name": name,
            "enabled": True,
            "configuration": default_config
        }
        
        result = self._make_request("POST", "/2fa/2/applications", payload)
        self.application_id = result.get("applicationId")
        print(f"✅ Created application: {self.application_id}")
        return self.application_id
    
    def get_or_create_application(self, name: str) -> str:
        """Get existing application or create new one"""
        try:
            # Try to get existing applications
            result = self._make_request("GET", "/2fa/2/applications")
            
            if "results" in result:
                for app in result["results"]:
                    if app["name"] == name:
                        self.application_id = app["applicationId"]
                        print(f"✅ Using existing application: {self.application_id}")
                        return self.application_id
            
            # If not found, create new one
            return self.create_application(name)
            
        except:
            # If listing fails, just create new one
            return self.create_application(name)
    
    def create_message_template(self, 
                              template_name: str,
                              message_text: str = "Your verification code is {{pin}}",
                              pin_length: int = 6,
                              pin_type: str = "NUMERIC",
                              sender_id: str = "Infobip") -> str:
        """
        Create a message template for sending PINs
        
        Args:
            template_name: Name to store this template under
            message_text: Message template with {{pin}} placeholder
            pin_length: Length of PIN (4-8 recommended)
            pin_type: NUMERIC, ALPHA, or ALPHANUMERIC
            sender_id: Sender ID shown to recipient
            
        Returns:
            Message ID
        """
        if not self.application_id:
            raise Exception("No application ID set. Create an application first.")
        
        payload = {
            "pinType": pin_type,
            "messageText": message_text,
            "pinLength": pin_length,
            "senderId": sender_id
        }
        
        path = f"/2fa/2/applications/{self.application_id}/messages"
        result = self._make_request("POST", path, payload)
        
        message_id = result.get("messageId")
        self.message_templates[template_name] = {
            "messageId": message_id,
            "pinLength": pin_length,
            "pinType": pin_type
        }
        
        print(f"✅ Created message template '{template_name}': {message_id}")
        return message_id
    
    def send_pin(self, 
                 to_number: str,
                 template_name: str = None,
                 message_id: str = None,
                 from_number: str = None,
                 placeholders: Dict[str, str] = None) -> Dict:
        """
        Send a PIN to a phone number
        
        Args:
            to_number: Recipient phone number (with country code)
            template_name: Name of template to use (or provide message_id)
            message_id: Direct message ID (if not using template_name)
            from_number: Optional sender number
            placeholders: Optional custom placeholders
            
        Returns:
            Dictionary with pinId and status
        """
        if not self.application_id:
            raise Exception("No application ID set. Create an application first.")
        
        # Get message ID from template name if provided
        if template_name and template_name in self.message_templates:
            message_id = self.message_templates[template_name]["messageId"]
        elif not message_id:
            raise Exception("Either template_name or message_id must be provided")
        
        payload = {
            "applicationId": self.application_id,
            "messageId": message_id,
            "to": to_number.replace("+", "")  # Remove + if present
        }
        
        if from_number:
            payload["from"] = from_number.replace("+", "")
            
        if placeholders:
            payload["placeholders"] = placeholders
        
        result = self._make_request("POST", "/2fa/2/pin", payload)
        
        pin_id = result.get("pinId")
        status = result.get("smsStatus", "UNKNOWN")
        
        print(f"📤 PIN sent to {to_number}")
        print(f"   PIN ID: {pin_id}")
        print(f"   Status: {status}")
        
        return {
            "pinId": pin_id,
            "to": to_number,
            "status": status,
            "ncStatus": result.get("ncStatus"),
            "sent_at": datetime.now().isoformat()
        }
    
    def verify_pin(self, pin_id: str, pin_code: str) -> Dict:
        """
        Verify a PIN code
        
        Args:
            pin_id: The PIN ID returned from send_pin
            pin_code: The PIN code entered by user
            
        Returns:
            Dictionary with verification result
        """
        payload = {"pin": str(pin_code)}
        
        path = f"/2fa/2/pin/{pin_id}/verify"
        result = self._make_request("POST", path, payload)
        
        verified = result.get("verified", False)
        attempts_remaining = result.get("attemptsRemaining", 0)
        pin_error = result.get("pinError")
        
        print(f"🔐 Verification attempt for PIN ID: {pin_id}")
        print(f"   Verified: {'✅ Yes' if verified else '❌ No'}")
        
        if not verified:
            if pin_error:
                print(f"   Error: {pin_error}")
            print(f"   Attempts remaining: {attempts_remaining}")
        
        return {
            "verified": verified,
            "pinId": pin_id,
            "attemptsRemaining": attempts_remaining,
            "pinError": pin_error,
            "verified_at": datetime.now().isoformat() if verified else None
        }
    
    def resend_pin(self, pin_id: str) -> Dict:
        """
        Resend a PIN using the same PIN ID
        
        Args:
            pin_id: The original PIN ID
            
        Returns:
            New send result
        """
        path = f"/2fa/2/pin/{pin_id}/resend"
        result = self._make_request("POST", path)
        
        new_pin_id = result.get("pinId")
        status = result.get("smsStatus", "UNKNOWN")
        
        print(f"🔄 PIN resent")
        print(f"   New PIN ID: {new_pin_id}")
        print(f"   Status: {status}")
        
        return result
    
    def get_pin_status(self, pin_id: str) -> Dict:
        """Get the current status of a PIN"""
        path = f"/2fa/2/pin/{pin_id}"
        return self._make_request("GET", path)


# Example usage and test functions
def demo_2fa_flow():
    """Demonstrate a complete 2FA flow"""
    
    # Use environment variable for API key (more secure)
    API_KEY = os.getenv("INFOBIP_API_KEY", "9ed382de07749bbd295f929ab45483c7-afb57924-e5c0-4735-b288-828c42b9226c")
    
    # Initialize client
    client = Infobip2FA(API_KEY)
    
    print("=== Infobip 2FA Demo ===\n")
    
    try:
        # Step 1: Create or get application
        app_id = client.get_or_create_application("My 2FA App")
        
        # Step 2: Create message templates
        client.create_message_template(
            template_name="login",
            message_text="Your login code is {{pin}}. Valid for 10 minutes.",
            pin_length=6,
            sender_id="MyApp"
        )
        
        client.create_message_template(
            template_name="transaction",
            message_text="Confirm transaction with code {{pin}}",
            pin_length=4,
            sender_id="MyBank"
        )
        
        # Step 3: Send a PIN
        print("\n📱 Sending PIN...")
        send_result = client.send_pin(
            to_number="+8801752304601",  # Your number
            template_name="login",
            from_number="+447491163443"
        )
        
        pin_id = send_result["pinId"]
        
        # Step 4: Simulate user entering PIN
        print("\n⏳ Waiting for user to receive SMS...")
        print("   (In production, the user would enter the received PIN)")
        
        # In real usage, you'd get this from user input
        user_pin = input("\nEnter the PIN you received: ")
        
        # Step 5: Verify the PIN
        verify_result = client.verify_pin(pin_id, user_pin)
        
        if verify_result["verified"]:
            print("\n✅ Success! User authenticated.")
        else:
            print(f"\n❌ Verification failed.")
            
            if verify_result["attemptsRemaining"] > 0:
                print("   User can try again.")
            else:
                print("   No attempts remaining. Need to send new PIN.")
                
                # Optionally resend
                retry = input("\nResend PIN? (y/n): ")
                if retry.lower() == 'y':
                    client.resend_pin(pin_id)
                    print("New PIN sent!")
        
    except Exception as e:
        print(f"\n❌ Error: {e}")


def secure_implementation_example():
    """Example of a more secure implementation"""
    
    class Secure2FAService:
        def __init__(self):
            # Load from secure configuration
            self.client = Infobip2FA(
                api_key=os.environ["INFOBIP_API_KEY"],
                base_url=os.environ.get("INFOBIP_BASE_URL", "2mel1m.api.infobip.com")
            )
            self.sessions = {}  # In production, use Redis or similar
            
        def initiate_verification(self, user_id: str, phone_number: str, action: str = "login"):
            """Start 2FA verification for a user"""
            
            # Check rate limiting
            if self._is_rate_limited(user_id):
                raise Exception("Too many verification attempts. Please try again later.")
            
            # Send PIN
            result = self.client.send_pin(
                to_number=phone_number,
                template_name=action
            )
            
            # Store session with expiry
            self.sessions[user_id] = {
                "pin_id": result["pinId"],
                "attempts": 0,
                "expires_at": datetime.now() + timedelta(minutes=10),
                "action": action
            }
            
            return {"success": True, "message": "Verification code sent"}
        
        def complete_verification(self, user_id: str, pin_code: str):
            """Complete 2FA verification"""
            
            # Get session
            session = self.sessions.get(user_id)
            if not session:
                raise Exception("No active verification session")
            
            # Check expiry
            if datetime.now() > session["expires_at"]:
                del self.sessions[user_id]
                raise Exception("Verification session expired")
            
            # Verify PIN
            result = self.client.verify_pin(session["pin_id"], pin_code)
            
            if result["verified"]:
                # Clean up session
                del self.sessions[user_id]
                return {"success": True, "action": session["action"]}
            else:
                # Update attempts
                session["attempts"] += 1
                
                if result["attemptsRemaining"] == 0:
                    del self.sessions[user_id]
                    raise Exception("Maximum attempts exceeded")
                
                return {
                    "success": False, 
                    "attempts_remaining": result["attemptsRemaining"]
                }
        
        def _is_rate_limited(self, user_id: str):
            """Check if user is rate limited"""
            # Implement rate limiting logic
            # In production, use Redis or similar
            return False


if __name__ == "__main__":
    # Run the demo
    demo_2fa_flow()