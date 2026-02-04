# main.py

print("🚀 AI Security Hackathon Project Started")


def ai_waf_check(user_input):
    blocked_keywords = ["ignore previous instructions", "system prompt", "bypass", "hack"]

    for word in blocked_keywords:
        if word.lower() in user_input.lower():
            return "❌ Potential Prompt Injection Detected!"

    return "✅ Input Safe"


# Test
test_input = input("Enter user prompt: ")
result = ai_waf_check(test_input)
print(result)
