import smtplib
from email.mime.text import MIMEText

msg = MIMEText("Test email - confirming SMTP credentials work")
msg["Subject"] = "SMTP Credentials Test"
msg["From"] = "<from address>"
msg["To"] = "<to address>"

with smtplib.SMTP("smtp.gmail.com", 587) as server: # 587 if using TLS, and 465 if using SSL or you can change the smtp service provider
    server.starttls()
    server.login("<server username>", "<server password>")
    server.sendmail("<to address>", ["<re-enter to address>"], msg.as_string())

    