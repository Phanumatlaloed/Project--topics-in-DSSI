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
                print(f"🔍 API Response: {response_data}")  # ✅ Debug API response

                # ✅ ตรวจสอบว่ามี key "sentiment" หรือไม่
                sentiment_data = response_data.get("sentiment", {})

                # ✅ ใช้ค่า "polarity" เป็นตัวบอก sentiment
                if "polarity" in sentiment_data:
                    return sentiment_data["polarity"]  # ✅ คืนค่า "positive", "negative", หรือ "neutral"

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

import ollama

import ollama

def summarize_reviews_with_ollama(reviews):
    """สรุปรีวิวสินค้าทั้งหมดโดยใช้ Ollama DeepSeek-Coder"""
    review_texts = " ".join([review.comment for review in reviews])

    if len(review_texts) < 50:
        return "❌ รีวิวมีจำนวนน้อยเกินไปที่จะสรุป"

    try:
        response = ollama.chat(model="deepseek-coder", messages=[
            {
                "role": "system",
                "content": (
                    "คุณเป็น AI ที่ช่วยสรุปความคิดเห็นของลูกค้า "
                    "นี่คือรายการรีวิวจากลูกค้าเกี่ยวกับสินค้านี้ "
                    "กรุณาวิเคราะห์แนวโน้มของรีวิว (เช่น เชิงบวก เชิงลบ หรือกลางๆ) "
                    "และสรุปข้อดีข้อเสียของสินค้าให้สั้นและเข้าใจง่าย ตอบฉันเป็นภาษาไทย"
                )
            },
            {"role": "user", "content": review_texts}
        ])
        return response["message"]["content"]
    except Exception as e:
        print(f"⚠️ Ollama Summarization Error: {e}")
        return "❌ ไม่สามารถสรุปความได้"


    
API_TRANSLATION_URL = "https://api.aiforthai.in.th/en-th-align"
API_KEY = "gK0Vz2qOEkRpEryj9HogwsD9rh4Zgjmd"

def translate_to_thai(text):
    """แปลข้อความจากอังกฤษเป็นไทย"""
    headers = {
        "Apikey": API_KEY,
        "Content-Type": "application/json",
    }
    payload = {"EN": text, "TH": ""}
    
    try:
        response = requests.post(API_TRANSLATION_URL, headers=headers, json=payload)
        if response.status_code == 200:
            result = response.json()
            return result.get("TH", "❌ แปลไม่สำเร็จ")
        else:
            return "❌ แปลไม่สำเร็จ"
    except:
        return "❌ แปลไม่สำเร็จ"
