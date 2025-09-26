# Test file with LLM security vulnerabilities
import openai
import os

# API key exposure
api_key = "tavo-sk-1234567890abcdef"  # Hardcoded API key
openai.api_key = api_key

# Prompt injection vulnerability
def get_user_input():
    user_input = input("Enter your prompt: ")
    return user_input

def generate_response():
    prompt = get_user_input()
    response = openai.ChatCompletion.create(
        model="gpt-3.5-turbo",
        messages=[{"role": "user", "content": prompt}]
    )
    return response.choices[0].message.content

# Model theft vulnerability
def save_model():
    # This could be used to exfiltrate model weights
    model_data = openai.Model.retrieve("gpt-3.5-turbo")
    with open("stolen_model.json", "w") as f:
        f.write(str(model_data))

if __name__ == "__main__":
    print(generate_response())