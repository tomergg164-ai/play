# בלנדורה — שרת (Node.js + PostgreSQL + PayPal)

API מאובטח: קטלוג, חשבונות, תמחור בצד השרת, הזמנות, PayPal Checkout אמיתי (Sandbox/Live), webhook מאומת, מעקב הזמנות, ביקורות, ולוח ניהול (API).

> **סטטוס: הקוד נכתב אך לא הורץ מול PostgreSQL ו-PayPal. עד שתבדקו ב-Sandbox אין לקבוע שהתשלום עובד.**

## הרצה מקומית
```bash
npm install
cp .env.example .env        # ומלאו ערכים
psql "$DATABASE_URL" -f schema.sql
export $(grep -v '^#' .env | xargs) && npm run seed   # מוצרים, מנהל וקופון WELCOME10
export $(grep -v '^#' .env | xargs) && npm start
```
## PayPal Sandbox
1. ב-developer.paypal.com צרו App במצב Sandbox, והעתיקו Client ID ו-Secret ל-`.env`.
2. הוסיפו Webhook לכתובת `https://<השרת-שלכם>/api/paypal/webhook` עם האירוע `PAYMENT.CAPTURE.COMPLETED`, והעתיקו את ה-Webhook ID ל-`PAYPAL_WEBHOOK_ID`.
3. בדקו הזמנה עם חשבון Sandbox קונה. מצב Live: `PAYPAL_ENV=live` + פרטי Live, רק אחרי בדיקות והשלמת הגדרת חשבון עסקי.

## פריסה
שרת: Render/Railway/Fly (פקודת הפעלה `npm start`, `NODE_ENV=production`, HTTPS). מסד נתונים: Neon/Render Postgres עם `PGSSL=1`.
חזית: GitHub Pages; הגדירו `ALLOWED_ORIGIN=https://<משתמש>.github.io`.

## נקודות קצה עיקריות
`GET /api/products` · `POST /api/quote` · `POST /api/orders` · `POST /api/orders/:id/paypal` → `POST /api/orders/:id/capture` ·
`POST /api/auth/register|login|logout` · `GET /api/orders/mine` · `GET /api/orders/:id` · `/api/admin/*` (stats, products, orders, customers, reviews, refund).

## אבטחה שמומשה
סיסמאות bcrypt, סשנים ב-PostgreSQL (cookie מאובטח), בדיקת Origin נגד CSRF, הגבלת קצב, helmet, שאילתות פרמטריות, אימות קלט, חישוב מחיר ואימות סכום PayPal בשרת, הגנה מכפילות (PayPal-Request-Id, מזהה עסקה ייחודי, נעילת שורה), חתימת webhook.

## עדיין לא קיים
איפוס סיסמה (דורש שירות אימייל), מועדפים וכתובות שמורות, העלאת תמונות (כרגע כתובת URL), תשלום בכרטיס מעבר ל-PayPal, וחיבור החזית (index.html) ל-API והקלקות לוח הניהול כממשק גרפי.
