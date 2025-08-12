import nodemailer from 'nodemailer'

// Define email content for different use cases
interface EmailContentType {
  title: string
  greeting: string
  message: string
  actionText: string
}

interface EmailContentMap {
  [key: string]: EmailContentType
}

const emailContent: EmailContentMap = {
  Registration: {
    title: 'Verify Your Registration',
    greeting: 'Welcome to Haulage Driver App!',
    message:
      'Thank you for registering with the Haulage Driver App. To complete your registration and verify your email address, please use the verification code below.',
    actionText:
      'Enter this code in the verification page to complete your registration process.',
  },
  completeOnboarding: {
    title: 'Complete Your Verification',
    greeting: 'Welcome Back!',
    message:
      "We noticed you're trying to sign in. Since you already have an account with us, please use the verification code below to complete your onboarding process.",
    actionText:
      'Enter this code in the verification page to complete your profile setup and access your account.',
  },
  forgotPassword: {
    title: 'Reset Your Password',
    greeting: 'Password Reset Request',
    message:
      'We received a request to reset your password for the Haulage Driver App. Please use the verification code below to confirm this request.',
    actionText:
      'Enter this code in the password reset page to create a new password for your account.',
  },
}

export const sendOtpEmail = async (
  email: string,
  otp: string,
  subject: string
) => {
  // Determine the email content based on subject
  const content = emailContent[subject] || emailContent.Registration

  // Split OTP into individual characters for better styling
  const otpChars = otp.split('')

  const transporter = nodemailer.createTransport({
    service: 'gmail',
    host: process.env.EMAIL_HOST,
    port: 587,
    secure: false,
    auth: {
      user: process.env.EMAIL_USERNAME,
      pass: process.env.EMAIL_PASSWORD,
    },
  })

  const mailOptions = {
    from: '"Haulage Driver App" <adeolusegun1000@gmail.com>',
    to: email,
    subject: `Your Verification Code for ${subject}`,
    text: `Your verification code is ${otp}. It expires in 5 minutes.`,
    html: `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>${content.title}</title>
      <style>
        @import url('https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;500;700&display=swap');
        
        body {
          font-family: 'Roboto', Arial, sans-serif;
          line-height: 1.6;
          color: #333333;
          margin: 0;
          padding: 0;
          background-color: #f4f4f4;
        }
        
        .email-container {
          max-width: 600px;
          margin: 0 auto;
          background-color: #ffffff;
          border-radius: 8px;
          overflow: hidden;
          box-shadow: 0 4px 8px rgba(0, 0, 0, 0.05);
        }
        
        .email-header {
          background-color: #1a4b84;
          color: #ffffff;
          padding: 30px;
          text-align: center;
        }
        
        .email-header h1 {
          margin: 0;
          font-size: 24px;
          font-weight: 700;
        }
        
        .email-body {
          padding: 30px;
          background-color: #ffffff;
        }
        
        .greeting {
          font-size: 18px;
          margin-bottom: 20px;
          font-weight: 500;
          color: #1a4b84;
        }
        
        .message {
          margin-bottom: 30px;
          font-size: 16px;
        }
        
        .otp-container {
          margin: 30px 0;
          text-align: center;
        }
        
        .otp-title {
          font-weight: 500;
          margin-bottom: 15px;
          font-size: 16px;
          color: #555555;
        }
        
        .otp-boxes {
          display: flex;
          justify-content: center;
          margin: 20px 0;
        }
        
        .otp-box {
          width: 50px;
          height: 60px;
          margin: 0 5px;
          background-color: #f7faff;
          border: 2px solid #1a4b84;
          border-radius: 8px;
          font-size: 28px;
          font-weight: 700;
          color: #1a4b84;
          display: flex;
          align-items: center;
          justify-content: center;
        }
        
        .expiry {
          background-color: #fff4f4;
          border-left: 4px solid #e74c3c;
          padding: 12px 15px;
          margin: 25px 0;
          color: #c0392b;
          font-size: 14px;
          border-radius: 4px;
        }
        
        .help-text {
          font-size: 14px;
          color: #666666;
          margin-top: 30px;
          padding-top: 20px;
          border-top: 1px solid #eeeeee;
        }
        
        .email-footer {
          background-color: #f4f7fa;
          padding: 20px 30px;
          text-align: center;
          font-size: 12px;
          color: #666666;
        }
        
        .company-info {
          margin-bottom: 10px;
        }

        /* Mobile responsiveness */
        @media only screen and (max-width: 480px) {
          .email-header {
            padding: 20px;
          }
          
          .email-body {
            padding: 20px;
          }
          
          .otp-box {
            width: 40px;
            height: 50px;
            font-size: 24px;
            margin: 0 3px;
          }
          
          .greeting {
            font-size: 16px;
          }
          
          .message {
            font-size: 14px;
          }
        }
      </style>
    </head>
    <body>
      <div class="email-container">
        <div class="email-header">
          <h1>Haulage Driver App</h1>
        </div>
        
        <div class="email-body">
          <p class="greeting">${content.greeting}</p>
          
          <p class="message">
            ${content.message}
          </p>
          
          <div class="otp-container">
            <p class="otp-title">Your Verification Code</p>
            <div class="otp-boxes">
              ${otpChars
                .map((char) => `<div class="otp-box">${char}</div>`)
                .join('')}
            </div>
          </div>
          
          <div class="expiry">
            <strong>⏱️ This verification code will expire in 5 minutes.</strong>
          </div>
          
          <p class="message">
            ${
              content.actionText
            } If you didn't request this verification, please ignore this email.
          </p>
          
          <p class="help-text">
            If you're having trouble with the verification process or have any questions, please contact our support team.
          </p>
        </div>
        
        <div class="email-footer">
          <div class="company-info">
            &copy; ${new Date().getFullYear()} Haulage Driver App. All Rights Reserved.
          </div>
          <div>
            This is an automated email, please do not reply.
          </div>
        </div>
      </div>
    </body>
    </html>
    `,
  }

  await transporter.sendMail(mailOptions)
}
