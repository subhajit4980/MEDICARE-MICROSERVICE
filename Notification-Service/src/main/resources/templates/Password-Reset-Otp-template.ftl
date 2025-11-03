<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
  <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
  <title>Password Reset OTP - Medicare</title>
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
margin: 30px auto;
background-color: #ffffff;
border-radius: 8px;
overflow: hidden;
box-shadow: 0 4px 12px rgba(0,0,0,0.1);
}
.banner {
background: linear-gradient(90deg, #007bff, #00c6ff);
text-align: center;
padding: 30px 20px;
color: #fff;
}
.banner h1 {
margin: 0;
font-size: 26px;
}
.content {
padding: 25px;
color: #333;
}
.content p {
margin-bottom: 18px;
font-size: 15px;
color: #555;
}
.otp-box {
text-align: center;
font-size: 24px;
font-weight: bold;
background-color: #f0f8ff;
color: #007bff;
padding: 12px 0;
border-radius: 6px;
margin: 25px 0;
letter-spacing: 2px;
}
.button {
display: inline-block;
background-color: #007bff;
color: #fff !important;
text-decoration: none;
padding: 12px 28px;
border-radius: 5px;
font-weight: bold;
font-size: 16px;
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
color: #007bff;
text-decoration: none;
}
</style>
</head>
<body>
<div class="container">
    <!-- Banner -->
    <div class="banner">
      <h1>Password Reset OTP</h1>
      <p style="margin-top: 8px; font-size: 16px;">Secure your Medicare account</p>
    </div>

    <!-- Content -->
    <div class="content">
      <p>We’ve received a request to reset the password for your <b>Medicare</b> account. To proceed, please use the following One-Time Password (OTP):</p>

      <div class="otp-box">${otp}</div>

      <p>This OTP is valid for <b>5 minutes</b> from the time of this email.</p>
      <p>If you did not request a password reset, please ignore this message — your account remains secure.</p>
      <p>For your safety, never share this OTP with anyone. Our support team will never ask for it.</p>

      <p>If you need assistance, contact us anytime at
        <a href="mailto:medicare.team13@gmail.com">medicare.team13@gmail.com</a>.
      </p>
      <p>Stay safe and healthy,<br><b>The Medicare Team</b></p>
    </div>

    <!-- Footer -->
    <div class="footer">
      <p>&copy; 2025 Medicare. All rights reserved.<br>
    </div>
  </div>
</body>
</html>
