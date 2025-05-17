import requests


API_URL = "https://api.aiforthai.in.th/ssense"
API_KEY = "gK0Vz2qOEkRpEryj9HogwsD9rh4Zgjmd"

def analyze_text(text):
    """วิเคราะห์ความคิดเห็นโดยใช้ AI For Thai API"""
    headers = {
        "Apikey": API_KEY,
        "Content-Type": "application/x-www-form-urlencoded",
    }
    payload = {"text": text}

    try:
        response = requests.post(API_URL, headers=headers, data=payload)

        if response.status_code == 200:
            try:
                response_data = response.json()
                print(f"🔍 API Response: {response_data}")  

               
                sentiment_data = response_data.get("sentiment", {})

                
                if "polarity" in sentiment_data:
                    return sentiment_data["polarity"]  

                print("⚠️ API Response ไม่มีค่า polarity")
                return None
            except ValueError:
                print("⚠️ API ไม่ได้ส่ง JSON กลับมา")
                return None
        else:
            print(f"⚠️ API Error: {response.status_code} - {response.text}")
            return None

    except requests.RequestException as e:
        print(f"⚠️ Request Error: {e}")
        return None

