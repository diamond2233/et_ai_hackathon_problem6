"""Known scam campaign fingerprints.

Incoming messages are matched against this corpus with TF-IDF cosine similarity.
A high match means we are not guessing — we are naming an active campaign, which
is what turns a verdict into intelligence.

In production this table is populated from I4C/NCRB advisories and partner bank
abuse feeds. The structure is identical; only the source changes.
"""
from typing import Dict, List

CAMPAIGNS: List[Dict] = [
    {
        "id": "CMP-DA-001",
        "name": "FedEx Customs Parcel — Narcotics Pretext",
        "threat": "digital_arrest",
        "first_seen": "2023-08",
        "text": "Sir your parcel booked from Mumbai to Taiwan has been seized by "
                "customs department. It contains 4 passports, 3 credit cards and 150 "
                "grams of MDMA drugs. An FIR has been registered against your Aadhaar "
                "number. Your case is being transferred to Mumbai Cyber Crime Branch. "
                "Press 1 to connect with the investigating officer.",
    },
    {
        "id": "CMP-DA-002",
        "name": "CBI Money Laundering — Verification Transfer",
        "threat": "digital_arrest",
        "first_seen": "2024-01",
        "text": "This is Inspector from CBI headquarters Delhi. Your bank account is "
                "linked to a money laundering case of 2 crore rupees under PMLA. A "
                "non bailable arrest warrant has been issued against you. You are "
                "under digital arrest. Do not disconnect this video call and do not "
                "inform any family member, this is a matter of national secrecy. To "
                "prove your funds are clean you must transfer the balance to the RBI "
                "verification account. The amount is fully refundable after clearance.",
    },
    {
        "id": "CMP-DA-003",
        "name": "TRAI SIM Deactivation Gateway",
        "threat": "digital_arrest",
        "first_seen": "2023-11",
        "text": "Your mobile number will be disconnected within 2 hours by TRAI. "
                "Twenty two illegal complaints have been registered against this "
                "number for harassment and fraudulent advertisement. Press 9 to speak "
                "to a TRAI officer. Your case is being forwarded to the cyber crime "
                "department of Mumbai police for further legal proceedings.",
    },
    {
        "id": "CMP-DA-004",
        "name": "Supreme Court Escrow Custody",
        "threat": "digital_arrest",
        "first_seen": "2024-06",
        "text": "You are speaking to the Enforcement Directorate. Under the observation "
                "of the Honourable Supreme Court you are being placed under digital "
                "custody for 24 hours. Keep your camera on at all times. You may not "
                "leave the room or contact anyone including your lawyer. All your "
                "assets must be moved to a Supreme Court monitored escrow account for "
                "audit. Failure to comply will result in immediate physical arrest by "
                "the local police station.",
    },
    {
        "id": "CMP-BF-001",
        "name": "SBI YONO KYC Expiry",
        "threat": "kyc_fraud",
        "first_seen": "2023-04",
        "text": "Dear Customer your SBI YONO account has been suspended today due to "
                "incomplete KYC. Your net banking will be blocked within 24 hours. "
                "Kindly update your PAN card immediately by clicking the link to "
                "reactivate your account. Ignore if already updated.",
    },
    {
        "id": "CMP-BF-002",
        "name": "Credit Card Reward Points Expiry",
        "threat": "bank_fraud",
        "first_seen": "2024-03",
        "text": "Dear Customer your credit card reward points worth Rs 8450 are "
                "expiring today. Redeem now before midnight by logging in and "
                "verifying your card number and CVV. Download our redemption app to "
                "claim instantly. Last reminder.",
    },
    {
        "id": "CMP-BF-003",
        "name": "AnyDesk Bank Support Takeover",
        "threat": "bank_fraud",
        "first_seen": "2023-09",
        "text": "I am calling from your bank customer care regarding the failed "
                "transaction on your account. To process the refund please install "
                "AnyDesk from Play Store and share the 9 digit code with me so I can "
                "check your screen. Do not disconnect, I am processing your refund now.",
    },
    {
        "id": "CMP-UPI-001",
        "name": "Wrong Transfer Refund Trick",
        "threat": "upi_fraud",
        "first_seen": "2023-02",
        "text": "Bhai maine galti se aapke account me 15000 rupees transfer kar diye "
                "hain. Please check your PhonePe. Kindly return the amount urgently my "
                "mother is in hospital. I am sending you a request please accept it "
                "and enter your UPI pin to return my money.",
    },
    {
        "id": "CMP-UPI-002",
        "name": "QR Code Receive-Money Inversion",
        "threat": "upi_fraud",
        "first_seen": "2023-07",
        "text": "Sir I want to buy your product on OLX. I am from army posted at "
                "Jammu so I cannot come personally. I am sending you a QR code, just "
                "scan it and enter your UPI pin to receive the advance payment of "
                "25000 in your account. Please do it fast I have duty.",
    },
    {
        "id": "CMP-PH-001",
        "name": "Income Tax Refund Phishing",
        "threat": "phishing",
        "first_seen": "2024-07",
        "text": "Dear taxpayer you are eligible for an income tax refund of Rs 24870. "
                "The amount has been approved but could not be credited due to invalid "
                "bank account details. Please verify your account number and IFSC on "
                "the link to receive the refund within 24 hours.",
    },
    {
        "id": "CMP-PH-002",
        "name": "Electricity Disconnection Tonight",
        "threat": "phishing",
        "first_seen": "2023-05",
        "text": "Dear consumer your electricity connection will be disconnected "
                "tonight at 9:30 pm because your previous month bill was not updated. "
                "Please immediately contact our electricity officer on this mobile "
                "number to avoid disconnection.",
    },
    {
        "id": "CMP-LT-001",
        "name": "KBC Lucky Draw Lottery",
        "threat": "lottery",
        "first_seen": "2022-11",
        "text": "Congratulations your mobile number has won 25 lakh rupees in the KBC "
                "lucky draw lottery. Your lucky number is 8858. To claim your prize "
                "money contact our manager on WhatsApp and pay the refundable GST "
                "processing fee of 12500 rupees to release the amount.",
    },
    {
        "id": "CMP-CR-001",
        "name": "Delivery Failed Address Update",
        "threat": "courier",
        "first_seen": "2024-02",
        "text": "Your package could not be delivered due to incomplete address "
                "information. Please update your delivery address and pay the pending "
                "customs charge of Rs 45 within 12 hours or the parcel will be "
                "returned to the sender.",
    },
    {
        "id": "CMP-JB-001",
        "name": "Telegram Task Prepaid Deposit",
        "threat": "job_scam",
        "first_seen": "2023-10",
        "text": "Hello I am HR from a digital marketing company. We offer part time "
                "work from home job. You just have to like and subscribe youtube "
                "videos and earn 3000 rupees daily. Join our telegram group to start. "
                "First complete a prepaid task of 5000 to unlock higher commission.",
    },
    {
        "id": "CMP-LN-001",
        "name": "Instant Loan App Harvest",
        "threat": "loan_scam",
        "first_seen": "2023-06",
        "text": "Congratulations you are pre approved for an instant personal loan of "
                "5 lakh rupees without any documents and without CIBIL check. Money "
                "will be credited in 10 minutes. Download our app now and pay the "
                "processing charge to activate your loan.",
    },
    {
        "id": "CMP-IV-001",
        "name": "WhatsApp Stock Tip Group",
        "threat": "investment",
        "first_seen": "2024-04",
        "text": "Join our exclusive VIP trading group. Our institutional analyst gives "
                "guaranteed returns of 30 percent monthly with zero risk. We have "
                "insider information on tomorrow's stock. Deposit through our partner "
                "platform and double your investment in 15 days. Only 5 seats left.",
    },
    {
        "id": "CMP-SX-001",
        "name": "Video Call Extortion",
        "threat": "sextortion",
        "first_seen": "2023-12",
        "text": "I have screen recorded your video call. I also have your full contact "
                "list from your phone. If you do not pay 50000 rupees within 2 hours I "
                "will upload this video on youtube and send it to all your family "
                "members and colleagues. I am from the cyber crime department and I "
                "can also arrest you for this.",
    },
    # Legitimate messages. Without these the model has no idea what "safe" looks
    # like and drifts toward flagging everything.
    {
        "id": "CMP-SAFE-001",
        "name": "Genuine bank debit alert",
        "threat": "safe",
        "first_seen": "n/a",
        "text": "Dear Customer, Rs 2499.00 has been debited from your account XX4471 on "
                "12-03-25 to VPA merchant@okhdfcbank. Not you? Call 18002586161. "
                "-HDFC Bank",
    },
    {
        "id": "CMP-SAFE-002",
        "name": "Genuine OTP notification",
        "threat": "safe",
        "first_seen": "n/a",
        "text": "123456 is your OTP for login. Valid for 10 minutes. Do not share this "
                "OTP with anyone including bank staff. -SBI",
    },
    {
        "id": "CMP-SAFE-003",
        "name": "Genuine delivery notification",
        "threat": "safe",
        "first_seen": "n/a",
        "text": "Your order has been shipped and will be delivered by tomorrow 7 PM. "
                "Track your package in the app under My Orders. No payment is due, "
                "your order is already prepaid.",
    },
]
