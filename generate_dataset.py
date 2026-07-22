#!/usr/bin/env python3
"""SentinelAI synthetic dataset generator.

Produces the demo corpus:
    dataset/scam_messages.json   500 labelled messages (incl. legitimate controls)
    dataset/complaints.json      500 complaint records
    dataset/hotspots.json        fraud hotspots with coordinates
    dataset/state_stats.json     per-state aggregates
    dataset/statistics.json      headline figures + monthly trend

Everything is seeded, so the dataset is reproducible across machines — which
matters when four people are building against the same demo.

Templates are composed from real reported scam grammar (I4C/NCRB advisories and
public bank warnings), then randomised over names, amounts, handles and
locations. No real victim data is used anywhere.

Usage:
    python scripts/generate_dataset.py
    python scripts/generate_dataset.py --messages 800 --complaints 800 --seed 7
"""
from __future__ import annotations

import argparse
import json
import os
import random
import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, List

OUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "dataset")

# --------------------------------------------------------------------- lookups

STATES: List[Dict] = [
    # name, lat, lng, population weight (relative fraud volume driver)
    {"state": "Maharashtra", "lat": 19.7515, "lng": 75.7139, "w": 13.0},
    {"state": "Uttar Pradesh", "lat": 26.8467, "lng": 80.9462, "w": 14.5},
    {"state": "Karnataka", "lat": 15.3173, "lng": 75.7139, "w": 9.5},
    {"state": "Delhi", "lat": 28.7041, "lng": 77.1025, "w": 8.5},
    {"state": "Telangana", "lat": 17.1232, "lng": 79.2089, "w": 7.5},
    {"state": "Gujarat", "lat": 22.2587, "lng": 71.1924, "w": 6.5},
    {"state": "Tamil Nadu", "lat": 11.1271, "lng": 78.6569, "w": 6.0},
    {"state": "Rajasthan", "lat": 27.0238, "lng": 74.2179, "w": 5.5},
    {"state": "West Bengal", "lat": 22.9868, "lng": 87.8550, "w": 5.0},
    {"state": "Madhya Pradesh", "lat": 22.9734, "lng": 78.6569, "w": 4.5},
    {"state": "Bihar", "lat": 25.0961, "lng": 85.3131, "w": 4.5},
    {"state": "Haryana", "lat": 29.0588, "lng": 76.0856, "w": 4.0},
    {"state": "Andhra Pradesh", "lat": 15.9129, "lng": 79.7400, "w": 3.5},
    {"state": "Punjab", "lat": 31.1471, "lng": 75.3412, "w": 3.0},
    {"state": "Kerala", "lat": 10.8505, "lng": 76.2711, "w": 2.5},
    {"state": "Odisha", "lat": 20.9517, "lng": 85.0985, "w": 2.5},
    {"state": "Jharkhand", "lat": 23.6102, "lng": 85.2799, "w": 2.5},
    {"state": "Assam", "lat": 26.2006, "lng": 92.9376, "w": 2.0},
    {"state": "Chhattisgarh", "lat": 21.2787, "lng": 81.8661, "w": 1.5},
    {"state": "Uttarakhand", "lat": 30.0668, "lng": 79.0193, "w": 1.2},
]

CITIES: Dict[str, List[Dict]] = {
    "Maharashtra": [{"c": "Mumbai", "lat": 19.0760, "lng": 72.8777},
                    {"c": "Pune", "lat": 18.5204, "lng": 73.8567},
                    {"c": "Nagpur", "lat": 21.1458, "lng": 79.0882}],
    "Uttar Pradesh": [{"c": "Lucknow", "lat": 26.8467, "lng": 80.9462},
                      {"c": "Noida", "lat": 28.5355, "lng": 77.3910},
                      {"c": "Varanasi", "lat": 25.3176, "lng": 82.9739}],
    "Karnataka": [{"c": "Bengaluru", "lat": 12.9716, "lng": 77.5946},
                  {"c": "Mysuru", "lat": 12.2958, "lng": 76.6394}],
    "Delhi": [{"c": "New Delhi", "lat": 28.6139, "lng": 77.2090},
              {"c": "Dwarka", "lat": 28.5921, "lng": 77.0460}],
    "Telangana": [{"c": "Hyderabad", "lat": 17.3850, "lng": 78.4867},
                  {"c": "Warangal", "lat": 17.9689, "lng": 79.5941}],
    "Gujarat": [{"c": "Ahmedabad", "lat": 23.0225, "lng": 72.5714},
                {"c": "Surat", "lat": 21.1702, "lng": 72.8311}],
    "Tamil Nadu": [{"c": "Chennai", "lat": 13.0827, "lng": 80.2707},
                   {"c": "Coimbatore", "lat": 11.0168, "lng": 76.9558}],
    "Rajasthan": [{"c": "Jaipur", "lat": 26.9124, "lng": 75.7873},
                  {"c": "Bharatpur", "lat": 27.2152, "lng": 77.5030}],
    "West Bengal": [{"c": "Kolkata", "lat": 22.5726, "lng": 88.3639},
                    {"c": "Asansol", "lat": 23.6739, "lng": 86.9524}],
    "Madhya Pradesh": [{"c": "Indore", "lat": 22.7196, "lng": 75.8577},
                       {"c": "Bhopal", "lat": 23.2599, "lng": 77.4126}],
    "Bihar": [{"c": "Patna", "lat": 25.5941, "lng": 85.1376},
              {"c": "Nalanda", "lat": 25.1372, "lng": 85.4438},
              {"c": "Gaya", "lat": 24.7955, "lng": 84.9994}],
    "Haryana": [{"c": "Gurugram", "lat": 28.4595, "lng": 77.0266},
                {"c": "Nuh", "lat": 28.1063, "lng": 77.0010}],
    "Andhra Pradesh": [{"c": "Visakhapatnam", "lat": 17.6868, "lng": 83.2185}],
    "Punjab": [{"c": "Ludhiana", "lat": 30.9010, "lng": 75.8573}],
    "Kerala": [{"c": "Kochi", "lat": 9.9312, "lng": 76.2673}],
    "Odisha": [{"c": "Bhubaneswar", "lat": 20.2961, "lng": 85.8245}],
    "Jharkhand": [{"c": "Jamtara", "lat": 23.9615, "lng": 86.8021},
                  {"c": "Ranchi", "lat": 23.3441, "lng": 85.3096}],
    "Assam": [{"c": "Guwahati", "lat": 26.1445, "lng": 91.7362}],
    "Chhattisgarh": [{"c": "Raipur", "lat": 21.2514, "lng": 81.6296}],
    "Uttarakhand": [{"c": "Dehradun", "lat": 30.3165, "lng": 78.0322}],
}

FIRST = ["Rahul", "Priya", "Amit", "Sneha", "Vikram", "Anjali", "Suresh", "Kavita",
         "Arjun", "Meera", "Rajesh", "Pooja", "Sanjay", "Divya", "Karthik", "Nisha",
         "Manoj", "Ritu", "Deepak", "Swati", "Imran", "Fatima", "Joseph", "Neha",
         "Gopal", "Lakshmi", "Farhan", "Ananya", "Vivek", "Shreya"]
LAST = ["Sharma", "Verma", "Patel", "Reddy", "Singh", "Nair", "Iyer", "Das", "Gupta",
        "Mehta", "Kulkarni", "Khan", "Bose", "Chauhan", "Rao", "Joshi", "Pillai",
        "Banerjee", "Yadav", "Mishra"]

BANKS = ["SBI", "HDFC Bank", "ICICI Bank", "Axis Bank", "Punjab National Bank",
         "Bank of Baroda", "Kotak Mahindra", "Canara Bank", "Union Bank"]
UPI_SUFFIX = ["okaxis", "okhdfcbank", "oksbi", "ybl", "paytm", "apl", "ibl"]
AGENCIES = ["CBI", "Enforcement Directorate", "Narcotics Control Bureau",
            "Cyber Crime Branch", "Customs Department", "TRAI", "Income Tax Department"]
COURIERS = ["FedEx", "DHL", "BlueDart", "DTDC", "India Post"]
SHORTENERS = ["bit.ly", "tinyurl.com", "cutt.ly", "rb.gy", "is.gd"]
FAKE_TLDS = ["xyz", "top", "online", "info", "club", "site", "buzz"]

CHANNELS = ["sms", "whatsapp", "email", "call_transcript"]


# ------------------------------------------------------------------- utilities

def rand_phone(rng: random.Random) -> str:
    return f"+91{rng.choice('6789')}{''.join(str(rng.randint(0, 9)) for _ in range(9))}"


def rand_upi(rng: random.Random) -> str:
    name = rng.choice(FIRST).lower() + str(rng.randint(10, 9999))
    return f"{name}@{rng.choice(UPI_SUFFIX)}"


def rand_url(rng: random.Random, brand: str = "") -> str:
    if rng.random() < 0.45:
        return f"http://{rng.choice(SHORTENERS)}/{uuid.uuid4().hex[:7]}"
    base = (brand or rng.choice(["sbi", "hdfc", "icici", "npci", "kyc", "india"])).lower()
    return f"http://{base}-{rng.choice(['secure', 'verify', 'update', 'kyc', 'refund'])}." \
           f"{rng.choice(FAKE_TLDS)}/{uuid.uuid4().hex[:6]}"


def rand_amount(rng: random.Random, lo: int, hi: int) -> int:
    return int(rng.randint(lo, hi) / 100) * 100


def rand_account(rng: random.Random) -> str:
    return "".join(str(rng.randint(0, 9)) for _ in range(rng.choice([11, 12, 14])))


def weighted_state(rng: random.Random) -> Dict:
    total = sum(s["w"] for s in STATES)
    pick = rng.uniform(0, total)
    acc = 0.0
    for s in STATES:
        acc += s["w"]
        if pick <= acc:
            return s
    return STATES[0]


# ------------------------------------------------------------ message builders
# Each builder returns the message body. Labels are attached by the caller.

def m_digital_arrest(rng: random.Random) -> str:
    agency = rng.choice(AGENCIES)
    officer = f"{rng.choice(['Inspector', 'DCP', 'ACP', 'Officer'])} {rng.choice(LAST)}"
    amount = rand_amount(rng, 200000, 9500000)
    variants = [
        f"This is {officer} from {agency}, Delhi headquarters. A parcel booked in your "
        f"name from Mumbai to Taiwan has been intercepted by {rng.choice(COURIERS)}. It "
        f"contains 4 fake passports and 140 grams of MDMA. An FIR has been registered "
        f"against your Aadhaar. You are now under digital arrest. Do not disconnect this "
        f"video call and do not inform any family member. To prove your innocence transfer "
        f"Rs {amount:,} to the RBI verification account {rand_account(rng)}. The amount is "
        f"fully refundable after clearance.",

        f"{agency} calling. Your bank account has been linked to a money laundering case "
        f"of Rs {amount:,} under PMLA Section 3. A non-bailable arrest warrant has been "
        f"issued in your name. You are being placed under digital custody for 24 hours "
        f"under Supreme Court observation. Keep your camera switched on at all times. Do "
        f"not contact anyone including your lawyer, this is a matter of national secrecy.",

        f"Your mobile number will be disconnected within 2 hours by TRAI. Twenty-two "
        f"complaints of harassment have been registered against this number. Press 9 to "
        f"speak to the {rng.choice(['Mumbai', 'Delhi', 'Bengaluru'])} Cyber Crime "
        f"department. Your case is being escalated for immediate legal proceedings and "
        f"arrest under IT Act Section 66.",

        f"I am {officer}, {agency}. Your Aadhaar number has been used to open 7 fraudulent "
        f"bank accounts in {rng.choice(['Kolkata', 'Surat', 'Jaipur'])}. This is a serious "
        f"offence. You are under digital arrest until verification is complete. Stay on "
        f"this Skype call. Transfer your entire account balance to the government escrow "
        f"account {rand_account(rng)} for audit. It will be returned within 3 hours.",

        f"URGENT: {agency} notice. A case has been registered against you under Section 420 "
        f"IPC and the Official Secrets Act. Your assets are being frozen. You will remain "
        f"under virtual arrest and 24 hour surveillance. Any attempt to contact family, "
        f"police or media will result in immediate physical arrest by your local station.",
    ]
    return rng.choice(variants)


def m_bank_fraud(rng: random.Random) -> str:
    bank = rng.choice(BANKS)
    amount = rand_amount(rng, 1500, 95000)
    variants = [
        f"Dear Customer, your {bank} account will be blocked within 24 hours due to "
        f"incomplete KYC. Kindly update your PAN immediately at {rand_url(rng)} to "
        f"reactivate. Ignore if already done. -{bank}",

        f"Dear Customer, Rs {amount:,} has been debited from your {bank} account for a "
        f"service you did not authorise. If this was not you, call {rand_phone(rng)} "
        f"immediately to reverse the transaction and share the OTP received on your phone.",

        f"I am calling from {bank} customer care about the failed transaction on your "
        f"account. To process your refund of Rs {amount:,} please install AnyDesk from "
        f"Play Store and share the 9-digit code with me so I can view your screen. Do not "
        f"disconnect, I am processing it now.",

        f"Dear Customer, your {bank} credit card reward points worth Rs {amount:,} expire "
        f"today at midnight. Redeem now at {rand_url(rng)} by verifying your card number, "
        f"expiry and CVV. Last reminder.",

        f"{bank} ALERT: Your debit card has been temporarily suspended due to suspicious "
        f"activity in {rng.choice(['Dubai', 'Bangkok', 'Lagos'])}. To unblock, confirm your "
        f"card details and the OTP sent to your registered mobile at {rand_url(rng)}.",
    ]
    return rng.choice(variants)


def m_upi_fraud(rng: random.Random) -> str:
    amount = rand_amount(rng, 2000, 60000)
    upi = rand_upi(rng)
    variants = [
        f"Bhai maine galti se aapke account me Rs {amount:,} transfer kar diye. Please "
        f"check your PhonePe. Kindly return urgently, my mother is admitted in hospital. "
        f"I am sending a request — just accept it and enter your UPI PIN to return the money.",

        f"Sir I want to buy your item on OLX. I am army personnel posted at "
        f"{rng.choice(['Jammu', 'Siachen', 'Leh'])} so I cannot come. I am sending a QR "
        f"code — scan it and enter your UPI PIN to receive the advance of Rs {amount:,}. "
        f"Please do it fast, I have duty in 10 minutes.",

        f"Your UPI ID will be deactivated tonight as per new NPCI rules. To keep it active, "
        f"approve the verification request of Rs 1 sent to your app and enter your UPI PIN. "
        f"Contact {upi} for help.",

        f"Congratulations! You have received a cashback of Rs {amount:,} from your last "
        f"transaction. Accept the collect request in your UPI app and enter your PIN to "
        f"credit the amount to your account.",
    ]
    return rng.choice(variants)


def m_phishing(rng: random.Random) -> str:
    amount = rand_amount(rng, 8000, 60000)
    variants = [
        f"Dear Taxpayer, you are eligible for an income tax refund of Rs {amount:,}. The "
        f"amount could not be credited due to invalid bank details. Verify your account "
        f"number and IFSC at {rand_url(rng, 'incometax')} within 24 hours.",

        f"Dear Consumer, your electricity connection will be disconnected tonight at 9:30 PM "
        f"as your previous bill was not updated. Contact our officer immediately on "
        f"{rand_phone(rng)} or pay at {rand_url(rng)} to avoid disconnection.",

        f"Your {rng.choice(['Netflix', 'Amazon Prime', 'Jio'])} subscription payment failed. "
        f"Update your payment method within 12 hours at {rand_url(rng)} or your account will "
        f"be permanently deleted. Click here to verify your identity.",

        f"IMPORTANT: Your Aadhaar has been suspended due to a mismatch in biometric records. "
        f"Re-verify immediately at {rand_url(rng, 'uidai')} or all linked services including "
        f"your bank account and ration card will be discontinued.",

        f"Dear Sir/Madam, we detected an unauthorised login to your account from "
        f"{rng.choice(['Moscow', 'Beijing', 'Karachi'])}. Secure your account NOW at "
        f"{rand_url(rng)}. Failure to act within 6 hours will result in permanent suspension.",
    ]
    return rng.choice(variants)


def m_lottery(rng: random.Random) -> str:
    prize = rng.choice([1500000, 2500000, 5000000, 7500000, 10000000])
    fee = rand_amount(rng, 4500, 45000)
    variants = [
        f"CONGRATULATIONS!! Your mobile number has WON Rs {prize:,} in the KBC Lucky Draw "
        f"Lottery. Your lucky number is {rng.randint(1000, 9999)}. To claim, contact our "
        f"manager on WhatsApp {rand_phone(rng)} and pay the refundable GST processing fee "
        f"of Rs {fee:,}.",

        f"Dear Winner, you have been selected in the {rng.choice(['Coca-Cola', 'Reliance', 'Tata'])} "
        f"Anniversary Lucky Draw for Rs {prize:,}. Send your name, address, Aadhaar copy and "
        f"the clearance charge of Rs {fee:,} to {rand_upi(rng)} to release your prize.",

        f"You have won a brand new {rng.choice(['Mahindra Thar', 'Royal Enfield', 'iPhone 16 Pro'])} "
        f"in our lucky customer draw! Only the registration fee of Rs {fee:,} is required. "
        f"Claim within 24 hours at {rand_url(rng)} or the prize goes to the next winner.",
    ]
    return rng.choice(variants)


def m_courier(rng: random.Random) -> str:
    courier = rng.choice(COURIERS)
    fee = rng.choice([25, 45, 60, 99, 150])
    variants = [
        f"{courier}: Your package could not be delivered due to an incomplete address. "
        f"Please update your details and pay the pending customs charge of Rs {fee} within "
        f"12 hours at {rand_url(rng)} or the parcel will be returned to sender.",

        f"Your consignment from {courier} is held at {rng.choice(['Mumbai', 'Delhi'])} "
        f"customs. Duty of Rs {rand_amount(rng, 1200, 8000):,} is pending. Pay at "
        f"{rand_url(rng)} to release. Unclaimed parcels are handed to the Narcotics Control "
        f"Bureau after 48 hours.",

        f"Delivery attempt failed for your {courier} shipment "
        f"{uuid.uuid4().hex[:10].upper()}. Reschedule your delivery here: {rand_url(rng)}. "
        f"A small redelivery fee of Rs {fee} applies.",
    ]
    return rng.choice(variants)


def m_job_scam(rng: random.Random) -> str:
    daily = rng.choice([1500, 2500, 3000, 5000])
    deposit = rand_amount(rng, 3000, 40000)
    variants = [
        f"Hello, I am HR {rng.choice(FIRST)} from a digital marketing company. We offer "
        f"part-time work from home. Just like and subscribe to YouTube videos and earn "
        f"Rs {daily:,} daily. Join our Telegram group to start. Complete one prepaid task "
        f"of Rs {deposit:,} to unlock higher commission slabs.",

        f"URGENT HIRING! Amazon data entry work from home. No experience needed. Earn "
        f"Rs {daily:,} per day, payment daily. Registration fee Rs {rand_amount(rng, 800, 5000):,} "
        f"(refundable with first salary). WhatsApp {rand_phone(rng)}.",

        f"Congratulations, your resume has been shortlisted for a {rng.choice(['TCS', 'Infosys', 'Wipro'])} "
        f"remote role at Rs {rand_amount(rng, 45000, 90000):,}/month. Pay the security "
        f"deposit of Rs {deposit:,} for your laptop and ID card to confirm joining.",
    ]
    return rng.choice(variants)


def m_loan_scam(rng: random.Random) -> str:
    amount = rng.choice([100000, 200000, 500000, 1000000])
    fee = rand_amount(rng, 1500, 12000)
    return rng.choice([
        f"Congratulations! You are PRE-APPROVED for an instant personal loan of "
        f"Rs {amount:,} without any documents and without CIBIL check. Money credited in "
        f"10 minutes. Download our app at {rand_url(rng)} and pay the processing charge of "
        f"Rs {fee:,} to activate.",

        f"Instant loan up to Rs {amount:,} at 0% interest for 3 months. No paperwork, no "
        f"salary slip. Approval in 5 minutes. Just install the app and pay a refundable "
        f"file charge of Rs {fee:,}. Limited period offer, apply at {rand_url(rng)}.",
    ])


def m_investment(rng: random.Random) -> str:
    pct = rng.choice([25, 30, 40, 50, 80])
    return rng.choice([
        f"Join our exclusive VIP trading group. Our institutional analyst gives GUARANTEED "
        f"returns of {pct}% monthly with zero risk. We have insider information on tomorrow's "
        f"stock. Deposit through our partner platform and double your investment in 15 days. "
        f"Only 5 seats left. WhatsApp {rand_phone(rng)}.",

        f"Crypto arbitrage opportunity — {pct}% guaranteed monthly returns, fully risk-free. "
        f"Minimum deposit Rs {rand_amount(rng, 25000, 200000):,} in USDT. Withdrawals "
        f"processed daily. Verified by our SEBI-registered partner. Register at {rand_url(rng)}.",
    ])


def m_sextortion(rng: random.Random) -> str:
    amount = rand_amount(rng, 20000, 300000)
    return rng.choice([
        f"I have screen-recorded your video call and I also have your full contact list. If "
        f"you do not pay Rs {amount:,} within 2 hours I will upload the video to YouTube and "
        f"send it to your family and colleagues. Pay to {rand_upi(rng)}. Do not tell anyone.",

        f"This is {rng.choice(['Inspector', 'SI'])} {rng.choice(LAST)} from the Cyber Crime "
        f"Department. A complaint has been filed against you for obscene content. Your video "
        f"is with us. Pay the settlement fee of Rs {amount:,} to close the case, otherwise "
        f"we will arrest you and inform your family.",
    ])


def m_safe(rng: random.Random) -> str:
    bank = rng.choice(BANKS)
    amount = rand_amount(rng, 200, 15000)
    return rng.choice([
        f"Dear Customer, Rs {amount:,}.00 has been debited from A/c XX{rng.randint(1000, 9999)} "
        f"on {rng.randint(1, 28):02d}-{rng.randint(1, 12):02d}-25 to VPA merchant@okhdfcbank. "
        f"Not you? Call 18002586161. -{bank}",

        f"{rng.randint(100000, 999999)} is your OTP for login. Valid for 10 minutes. Do not "
        f"share this OTP with anyone including bank staff. -{bank}",

        f"Your order #{rng.randint(100000000, 999999999)} has been shipped and will be "
        f"delivered by tomorrow 7 PM. Track it in the app under My Orders. No payment is due, "
        f"your order is already prepaid.",

        f"Reminder: your appointment at {rng.choice(['Apollo', 'Fortis', 'Max'])} Clinic is "
        f"scheduled for tomorrow at {rng.randint(9, 17)}:00. Please arrive 15 minutes early. "
        f"To reschedule call the clinic reception.",

        f"Hi {rng.choice(FIRST)}, this is a reminder that your electricity bill of "
        f"Rs {amount:,} is due on the {rng.randint(10, 28)}th. Pay through the official app "
        f"or your bank's biller section. Do not share your account details with anyone.",

        f"Dear Customer, your {bank} statement for the last month is now available in "
        f"NetBanking and the mobile app. No action is required.",
    ])


BUILDERS = [
    ("digital_arrest", m_digital_arrest, 0.20),
    ("bank_fraud", m_bank_fraud, 0.14),
    ("upi_fraud", m_upi_fraud, 0.11),
    ("phishing", m_phishing, 0.13),
    ("lottery", m_lottery, 0.07),
    ("courier", m_courier, 0.07),
    ("job_scam", m_job_scam, 0.06),
    ("loan_scam", m_loan_scam, 0.04),
    ("investment", m_investment, 0.04),
    ("sextortion", m_sextortion, 0.03),
    ("safe", m_safe, 0.11),
]

SEVERITY_BAND = {
    "digital_arrest": (88, 99), "sextortion": (85, 97), "bank_fraud": (72, 92),
    "upi_fraud": (70, 90), "phishing": (65, 88), "investment": (68, 88),
    "loan_scam": (60, 82), "job_scam": (58, 80), "lottery": (66, 88),
    "courier": (55, 80), "safe": (2, 18),
}


def generate_messages(n: int, rng: random.Random) -> List[Dict]:
    out: List[Dict] = []
    labels, builders, weights = zip(*BUILDERS)
    now = datetime.now(timezone.utc)

    for i in range(n):
        label = rng.choices(labels, weights=weights, k=1)[0]
        builder = dict(zip(labels, builders))[label]
        text = builder(rng)
        lo, hi = SEVERITY_BAND[label]
        st = weighted_state(rng)
        city = rng.choice(CITIES.get(st["state"], [{"c": st["state"]}]))

        if label == "digital_arrest":
            channel = rng.choices(CHANNELS, weights=[0.15, 0.3, 0.05, 0.5])[0]
        elif label == "phishing":
            channel = rng.choices(CHANNELS, weights=[0.35, 0.15, 0.5, 0.0])[0]
        else:
            channel = rng.choices(CHANNELS, weights=[0.4, 0.35, 0.15, 0.1])[0]

        out.append({
            "id": f"MSG{i + 1:04d}",
            "text": text,
            "label": label,
            "is_scam": label != "safe",
            "channel": channel,
            "expected_risk": rng.randint(lo, hi),
            "sender": rand_phone(rng) if channel in ("sms", "whatsapp", "call_transcript")
                      else f"{rng.choice(['alert', 'noreply', 'service', 'secure'])}@"
                           f"{rng.choice(['mail-verify', 'secure-update', 'bank-alert'])}."
                           f"{rng.choice(FAKE_TLDS)}",
            "language": rng.choices(["en", "hi", "hinglish"], weights=[0.72, 0.12, 0.16])[0],
            "state": st["state"],
            "city": city["c"],
            "reported_at": (now - timedelta(
                days=rng.randint(0, 364), hours=rng.randint(0, 23))).isoformat(),
        })
    return out


def generate_complaints(n: int, rng: random.Random) -> List[Dict]:
    out: List[Dict] = []
    now = datetime.now(timezone.utc)
    labels, _, weights = zip(*BUILDERS)
    scam_labels = [l for l in labels if l != "safe"]
    scam_weights = [w for l, w in zip(labels, weights) if l != "safe"]

    loss_band = {
        "digital_arrest": (150000, 8500000), "investment": (100000, 4000000),
        "sextortion": (15000, 400000), "bank_fraud": (8000, 900000),
        "upi_fraud": (2000, 250000), "phishing": (3000, 350000),
        "loan_scam": (2000, 120000), "job_scam": (5000, 300000),
        "lottery": (8000, 500000), "courier": (500, 60000),
    }
    statuses = ["open", "under_review", "escalated", "resolved", "closed"]
    status_w = [0.30, 0.26, 0.16, 0.18, 0.10]

    for i in range(n):
        scam = rng.choices(scam_labels, weights=scam_weights, k=1)[0]
        st = weighted_state(rng)
        city = rng.choice(CITIES.get(st["state"], [{"c": st["state"], "lat": st["lat"],
                                                    "lng": st["lng"]}]))
        lo, hi = loss_band[scam]
        # Most victims lose modest amounts; a long tail loses everything.
        amount = rand_amount(rng, lo, hi) if rng.random() < 0.28 else rand_amount(rng, lo, (lo + hi) // 4)
        recovered = rng.random() < 0.22

        # Digital arrest cases skew older-victim and longer-duration.
        age = rng.randint(52, 78) if scam == "digital_arrest" else rng.randint(19, 68)

        created = now - timedelta(days=rng.randint(0, 364), hours=rng.randint(0, 23),
                                  minutes=rng.randint(0, 59))

        out.append({
            "complaint_id": f"CYB{created.strftime('%y%m')}{i + 1:05d}",
            "victim_name": f"{rng.choice(FIRST)} {rng.choice(LAST)}",
            "victim_age": age,
            "scam_type": scam,
            "channel": rng.choice(CHANNELS),
            "description": _complaint_text(scam, amount, rng),
            "amount_lost": float(amount),
            "amount_recovered": float(rand_amount(rng, 0, amount // 2)) if recovered else 0.0,
            "state": st["state"],
            "city": city["c"],
            "lat": round(city.get("lat", st["lat"]) + rng.uniform(-0.06, 0.06), 5),
            "lng": round(city.get("lng", st["lng"]) + rng.uniform(-0.06, 0.06), 5),
            "suspect_contact": rng.choice([rand_phone(rng), rand_upi(rng), rand_account(rng)]),
            "status": rng.choices(statuses, weights=status_w, k=1)[0],
            "risk_score": rng.randint(*SEVERITY_BAND[scam]),
            "reported_within_golden_hour": rng.random() < 0.31,
            "created_at": created.isoformat(),
            "updated_at": (created + timedelta(days=rng.randint(0, 20))).isoformat(),
        })
    return out


def _complaint_text(scam: str, amount: int, rng: random.Random) -> str:
    t = {
        "digital_arrest": f"Received a video call from a person in uniform claiming to be from "
                          f"{rng.choice(AGENCIES)}. Was told a parcel in my name contained narcotics "
                          f"and that I was under digital arrest. Kept on video call for "
                          f"{rng.randint(4, 38)} hours and told not to contact family. Transferred "
                          f"Rs {amount:,} for 'verification' before realising it was fraud.",
        "bank_fraud": f"Caller claimed to be from bank customer care about a blocked card. Was asked "
                      f"to install a screen-sharing app and share the OTP. Rs {amount:,} was debited "
                      f"in {rng.randint(2, 6)} transactions within minutes.",
        "upi_fraud": f"Received a message about money transferred by mistake. Accepted the collect "
                     f"request and entered my UPI PIN to return it. Rs {amount:,} was debited "
                     f"instead of credited.",
        "phishing": f"Clicked a link in an SMS about a pending refund and entered my net banking "
                    f"credentials on a page that looked exactly like my bank's site. "
                    f"Rs {amount:,} was withdrawn the same evening.",
        "lottery": f"Was told I had won a lottery and paid Rs {amount:,} in instalments as GST and "
                   f"clearance charges. No prize was ever received and the number is now switched off.",
        "courier": f"Got an SMS that my parcel was held at customs. Paid Rs {amount:,} through the "
                   f"link provided. The tracking ID does not exist on the courier's official site.",
        "job_scam": f"Joined a Telegram group offering paid tasks. Received small payouts initially, "
                    f"then deposited Rs {amount:,} to unlock withdrawals. The group deleted my account.",
        "loan_scam": f"Installed an instant loan app and paid Rs {amount:,} in processing fees. The "
                     f"loan never arrived and the app began contacting people in my contact list.",
        "investment": f"Joined a WhatsApp trading group promising guaranteed monthly returns. Invested "
                      f"Rs {amount:,} over {rng.randint(2, 9)} weeks. The platform showed profits but "
                      f"blocked all withdrawal requests.",
        "sextortion": f"Received a video call from an unknown number followed by blackmail threats "
                      f"with a morphed recording. Paid Rs {amount:,} before reporting; the demands "
                      f"continued afterwards.",
    }
    return t.get(scam, f"Financial fraud reported with a loss of Rs {amount:,}.")


def build_hotspots(complaints: List[Dict]) -> List[Dict]:
    agg: Dict[str, Dict] = {}
    for c in complaints:
        key = f"{c['city']}|{c['state']}"
        if key not in agg:
            agg[key] = {"name": c["city"], "state": c["state"], "lat": c["lat"],
                        "lng": c["lng"], "complaints": 0, "amount_lost": 0.0,
                        "types": {}}
        a = agg[key]
        a["complaints"] += 1
        a["amount_lost"] += c["amount_lost"]
        a["types"][c["scam_type"]] = a["types"].get(c["scam_type"], 0) + 1

    out = []
    for a in agg.values():
        dominant = max(a["types"].items(), key=lambda kv: kv[1])[0]
        if a["complaints"] >= 22:
            risk = "critical"
        elif a["complaints"] >= 14:
            risk = "high"
        elif a["complaints"] >= 7:
            risk = "medium"
        else:
            risk = "low"
        out.append({
            "name": a["name"], "state": a["state"],
            "lat": round(a["lat"], 4), "lng": round(a["lng"], 4),
            "complaints": a["complaints"],
            "amount_lost": round(a["amount_lost"], 2),
            "risk_level": risk,
            "dominant_scam": dominant,
            "scam_breakdown": a["types"],
        })
    return sorted(out, key=lambda h: -h["complaints"])


def build_state_stats(complaints: List[Dict]) -> List[Dict]:
    agg: Dict[str, Dict] = {}
    for c in complaints:
        s = agg.setdefault(c["state"], {"state": c["state"], "complaints": 0,
                                        "amount_lost": 0.0, "digital_arrest": 0})
        s["complaints"] += 1
        s["amount_lost"] += c["amount_lost"]
        if c["scam_type"] == "digital_arrest":
            s["digital_arrest"] += 1

    out = []
    for s in agg.values():
        if s["complaints"] >= 45:
            risk = "critical"
        elif s["complaints"] >= 28:
            risk = "high"
        elif s["complaints"] >= 14:
            risk = "medium"
        else:
            risk = "low"
        meta = next((x for x in STATES if x["state"] == s["state"]), STATES[0])
        out.append({**s, "amount_lost": round(s["amount_lost"], 2), "risk_level": risk,
                    "lat": meta["lat"], "lng": meta["lng"]})
    return sorted(out, key=lambda x: -x["complaints"])


def build_statistics(complaints: List[Dict], messages: List[Dict]) -> Dict:
    total_loss = sum(c["amount_lost"] for c in complaints)
    recovered = sum(c["amount_recovered"] for c in complaints)
    da = [c for c in complaints if c["scam_type"] == "digital_arrest"]

    by_type: Dict[str, Dict] = {}
    for c in complaints:
        t = by_type.setdefault(c["scam_type"], {"count": 0, "amount": 0.0})
        t["count"] += 1
        t["amount"] += c["amount_lost"]

    monthly: Dict[str, Dict] = {}
    for c in complaints:
        month = c["created_at"][:7]
        m = monthly.setdefault(month, {"month": month, "complaints": 0,
                                       "amount_lost": 0.0, "digital_arrest": 0})
        m["complaints"] += 1
        m["amount_lost"] += c["amount_lost"]
        if c["scam_type"] == "digital_arrest":
            m["digital_arrest"] += 1

    golden = sum(1 for c in complaints if c["reported_within_golden_hour"])

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "totals": {
            "complaints": len(complaints),
            "messages_in_corpus": len(messages),
            "scam_messages": sum(1 for m in messages if m["is_scam"]),
            "legitimate_messages": sum(1 for m in messages if not m["is_scam"]),
            "total_loss": round(total_loss, 2),
            "total_recovered": round(recovered, 2),
            "recovery_rate_pct": round(recovered / total_loss * 100, 2) if total_loss else 0,
            "avg_loss": round(total_loss / len(complaints), 2) if complaints else 0,
            "digital_arrest_cases": len(da),
            "digital_arrest_loss": round(sum(c["amount_lost"] for c in da), 2),
            "golden_hour_reporting_pct": round(golden / len(complaints) * 100, 2) if complaints else 0,
            "states_affected": len({c["state"] for c in complaints}),
        },
        "by_type": [
            {"scam_type": k, "count": v["count"], "amount_lost": round(v["amount"], 2),
             "share_pct": round(v["count"] / len(complaints) * 100, 2)}
            for k, v in sorted(by_type.items(), key=lambda kv: -kv[1]["count"])
        ],
        "monthly": [
            {**v, "amount_lost": round(v["amount_lost"], 2)}
            for v in sorted(monthly.values(), key=lambda x: x["month"])
        ],
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Generate the SentinelAI demo dataset")
    ap.add_argument("--messages", type=int, default=500)
    ap.add_argument("--complaints", type=int, default=500)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", type=str, default=OUT_DIR)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    os.makedirs(args.out, exist_ok=True)

    print(f"Generating dataset (seed={args.seed}) …")
    messages = generate_messages(args.messages, rng)
    complaints = generate_complaints(args.complaints, rng)
    hotspots = build_hotspots(complaints)
    states = build_state_stats(complaints)
    stats = build_statistics(complaints, messages)

    files = {
        "scam_messages.json": messages,
        "complaints.json": complaints,
        "hotspots.json": hotspots,
        "state_stats.json": states,
        "statistics.json": stats,
    }
    for name, payload in files.items():
        path = os.path.join(args.out, name)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
        size = os.path.getsize(path) / 1024
        count = len(payload) if isinstance(payload, list) else 1
        print(f"  {name:22s} {count:>5} records  {size:>7.1f} KB")

    t = stats["totals"]
    print(f"\nSummary")
    print(f"  Scam / legit messages : {t['scam_messages']} / {t['legitimate_messages']}")
    print(f"  Digital arrest cases  : {t['digital_arrest_cases']}")
    print(f"  Total reported loss   : Rs {t['total_loss']:,.0f}")
    print(f"  Hotspots              : {len(hotspots)} across {t['states_affected']} states")
    print(f"\nDone. Load into MongoDB with:  python -m app.services.seed")


if __name__ == "__main__":
    main()
