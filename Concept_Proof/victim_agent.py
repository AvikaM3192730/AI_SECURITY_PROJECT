def run_agent(input_text):
    print("\n🤖 Worker Agent Processing...\n")

    # Simulating dangerous behavior
    if "send email" in input_text.lower():
        print("📧 Sending email to attacker@example.com")
    
    elif "delete file" in input_text.lower():
        print("🗑️ Deleting important files...")
    
    else:
        print("✅ Normal response:", input_text) 
