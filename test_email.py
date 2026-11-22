import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

# .env ফাইল থেকে ডেটা লোড করা
load_dotenv()

sender_email = os.getenv("SMTP_USER")
password = os.getenv("SMTP_PASSWORD")
receiver_email = "2304026@uftb.ac.bd"

print(f"Attempting to send email from: {sender_email}")
print(f"To: {receiver_email}")

if not sender_email or not password:
    print("❌ Error: SMTP_USER or SMTP_PASSWORD is missing in .env file. Please check your .env file.")
else:
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = "SiteWatch Test Email"
    body = "Congratulations! Your SiteWatch tool can send emails successfully."
    msg.attach(MIMEText(body, 'plain'))

    try:
        # Gmail SMTP সার্ভারে কানেক্ট
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, password)
        text = msg.as_string()
        server.sendmail(sender_email, receiver_email, text)
        server.quit()
        print("✅ Email sent successfully! Please check your inbox.")
    except Exception as e:
        print(f"❌ Failed to send email. Error: {e}")
