<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
  <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
  <title>Welcome to Medicare!</title>
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
font-size: 28px;
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
      <h1>Welcome to Medicare 🎉</h1>
      <p style="margin-top: 8px; font-size: 16px;">Your trusted healthcare partner</p>
    </div>

    <!-- Content -->
    <div class="content">
      <p>Dear ${Name},</p>
      <p>We’re thrilled to welcome you to <b>Medicare</b>, your one-stop destination for medical products and medicines.</p>
      <p>At <b>Medicare</b>, we’re committed to providing top-quality products, reliable service, and a smooth shopping experience for your health and wellness needs.</p>
      <p>Start exploring our wide range of offerings by clicking the button below:</p>

      <p style="text-align:center;">
        <a href="${medicareWebsiteUrl}" class="button">Explore Now</a>
      </p>

      <p>If you have any questions or need assistance, our support team is always ready to help you at
        <a href="mailto:medicare.team13@gmail.com">medicare.team13@gmail.com</a>.
      </p>
      <p>Thank you for choosing <b>Medicare</b>. We look forward to serving you!</p>
      <p>Best regards,<br><b>The Medicare Team</b></p>
    </div>

    <!-- Footer -->
    <div class="footer">
      <p>&copy; 2025 Medicare. All rights reserved.<br>
      <a href="${medicareWebsiteUrl}">Visit our website</a></p>
    </div>
  </div>
</body>
</html>
