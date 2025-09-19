<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Account Verification OTP</title>
  <style>
    body {
font-family: Arial, sans-serif;
line-height: 1.6;
background-color: #f4f4f4;
margin: 0;
padding: 0;
}
.container {
max-width: 600px;
margin: 20px auto;
background-color: #ffffff;
border-radius: 8px;
overflow: hidden;
box-shadow: 0 4px 12px rgba(0,0,0,0.1);
}
.banner {
background: linear-gradient(90deg, #4e73df, #1cc88a);
text-align: center;
padding: 20px;
}
.banner img {
max-width: 120px;
}
.content {
padding: 25px;
color: #333;
}
h1 {
color: #4e73df;
font-size: 22px;
}
p {
margin-bottom: 16px;
font-size: 15px;
color: #555;
}
.otp {
display: inline-block;
background: #f8f9fc;
border: 2px dashed #4e73df;
padding: 12px 20px;
font-weight: bold;
font-size: 22px;
color: #2c3e50;
border-radius: 6px;
margin: 20px 0;
}
.footer {
background: #f1f1f1;
text-align: center;
padding: 15px;
font-size: 13px;
color: #777;
}
.footer a {
color: #4e73df;
text-decoration: none;
}
</style>
</head>
<body>
<div class="container">
    <!-- Banner -->
    <div class="banner">
      <img src="https://img.icons8.com/ios-filled/100/ffffff/security-checked.png" alt="Verify"/>
      <h2 style="color:#fff; margin-top:10px;">Account Verification</h2>
    </div>

    <!-- Content -->
    <div class="content">
      <h1>Hello, ${Name} 👋</h1>
      <p>Welcome to <b>Medicare</b>! To complete your registration and verify your account, please use the One-Time Password (OTP) provided below:</p>

      <p class="otp">${otp}</p>

      <p>This OTP is valid for <b>5 minutes</b>. Enter it on the verification page to activate your account.</p>
      <p>If you did not request this, simply ignore this email.</p>
      <p><b>⚠ Security Tip:</b> Never share your OTP with anyone. Our team will never ask for it.</p>
      <p>If you face any issues, contact us at
        <a href="mailto:medicare.team13@gmail.com">medicare.team13@gmail.com</a>.
      </p>
      <p>Thank you for trusting <b>Medicare</b>.<br>
      – The Medicare Team</p>
    </div>

    <!-- Footer -->
    <div class="footer">
      <p>&copy; 2025 Medicare. All rights reserved.<br>
      <a href="https://your-domain.com">Visit our website</a></p>
    </div>
  </div>
</body>
</html>
