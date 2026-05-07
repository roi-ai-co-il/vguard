import { ArrowLeft } from 'lucide-react'

export default function Accessibility() {
  return (
    <div className="min-h-screen bg-(--color-bg) text-(--color-fg)">
      <div className="max-w-3xl mx-auto px-4 sm:px-6 py-12 sm:py-16">
        <div className="flex items-center justify-between mb-10">
          <a
            href="/"
            className="inline-flex items-center gap-2 font-mono text-[11px] sm:text-xs text-(--color-fg-dim) hover:text-(--color-fg) transition-colors"
          >
            <ArrowLeft size={14} aria-hidden="true" />
            <span>V-Guards</span>
          </a>
          <span className="font-mono text-[10px] sm:text-[11px] text-(--color-fg-dim) tracking-widest uppercase">
            Accessibility · נגישות
          </span>
        </div>

        <h1 className="text-3xl sm:text-4xl font-bold tracking-tight mb-2">הצהרת נגישות</h1>
        <p className="text-(--color-fg-muted) text-sm mb-10">
          עודכן לאחרונה: 7 במאי 2026
        </p>

        <div dir="rtl" className="space-y-6 text-sm sm:text-base leading-relaxed text-(--color-fg-muted)">
          <Section title="הצהרה כללית">
            <p>
              ROI AI מחויבת להנגיש את אתר V-Guards (<a href="https://v-guards.com" className="text-(--color-accent) hover:underline">https://v-guards.com</a>) למרבית האוכלוסייה, לרבות אנשים עם מוגבלות, בהתאם לחוק שוויון זכויות לאנשים עם מוגבלות, התשנ"ח-1998, ולתקנות שוויון זכויות לאנשים עם מוגבלות (התאמות נגישות לשירות), התשע"ג-2013.
            </p>
          </Section>

          <Section title="רמת התאמה">
            <p>
              האתר נבנה לפי הנחיות התקן הישראלי ת"י 5568 ברמת AA, המבוסס על מסמך התקן הבינלאומי
              <span dir="ltr"> WCAG 2.1 AA</span>. אנו פועלים באופן שוטף לשפר את חוויית הגלישה לכלל המשתמשים.
            </p>
          </Section>

          <Section title="כלי הנגישות באתר">
            <p>
              כפתור הנגישות הצף בפינה הימנית-תחתונה של המסך מאפשר התאמות אישיות:
            </p>
            <ul className="list-disc pr-5 space-y-1">
              <li>הגדלה / הקטנה של גודל הטקסט (75% עד 150%)</li>
              <li>מצב ניגודיות גבוהה</li>
              <li>הדגשת קישורים בקו תחתון</li>
              <li>השהיית אנימציות ותנועה אוטומטית</li>
              <li>איפוס מלא של ההגדרות לברירת המחדל</li>
            </ul>
            <p>
              ההעדפות נשמרות מקומית בדפדפן (localStorage) ונטענות אוטומטית בביקור הבא.
            </p>
          </Section>

          <Section title="התאמות נגישות שכבר מוטמעות">
            <ul className="list-disc pr-5 space-y-1">
              <li>ניגודיות צבעים מתאימה לרמת AA</li>
              <li>תוויות ARIA לכל הפקדים האינטראקטיביים</li>
              <li>ניווט מלא במקלדת</li>
              <li>קישור "דלג לתוכן הראשי" בראש העמוד</li>
              <li>תיוג שפה (lang) ויחס כיוון (dir) על אזורים בעברית</li>
              <li>זיהוי <span dir="ltr">prefers-reduced-motion</span> של מערכת ההפעלה</li>
              <li>טפסים עם תוויות מקושרות (label) והודעות שגיאה ברורות</li>
              <li>פוקוס נראה (focus-visible) על כל הפקדים</li>
            </ul>
          </Section>

          <Section title="חלקים שעדיין דורשים שיפור">
            <p>
              מספר אזורים באתר עדיין נמצאים בתהליך התאמה לרמת AAA, ביניהם:
            </p>
            <ul className="list-disc pr-5 space-y-1">
              <li>הגלובוס האינטראקטיבי בעמוד הבית — ויזואלי בלבד; הנתונים זמינים גם כרשימה טקסטואלית מתחתיו.</li>
              <li>סרטוני המחשה ואייקונים ב-Bento — להם תמיד טקסט מתאר.</li>
            </ul>
            <p>
              אנו פועלים להמשך שיפור החוויה לכל הגולשים.
            </p>
          </Section>

          <Section title="פנייה לרכז נגישות">
            <p>
              נתקלת בבעיית נגישות, או יש לך משוב? נשמח לדעת. נחזור אליך בתוך 7 ימי עסקים.
            </p>
            <ul className="list-none space-y-1">
              <li>
                <span className="text-(--color-fg)">רכז הנגישות:</span> Roy Argaman
              </li>
              <li>
                <span className="text-(--color-fg)">דוא"ל:</span>{' '}
                <a href="mailto:infovguards@gmail.com" className="text-(--color-accent) hover:underline">
                  infovguards@gmail.com
                </a>
              </li>
              <li>
                <span className="text-(--color-fg)">מועד פנייה:</span> כל יום, 24/7
              </li>
            </ul>
          </Section>

          <Section title="עדכון ההצהרה">
            <p>
              הצהרת נגישות זו נכתבה ב-7 במאי 2026 ותעודכן מעת לעת בהתאם לשיפורים באתר ובתשתית הנגישות.
            </p>
          </Section>
        </div>
      </div>
    </div>
  )
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section>
      <h2 className="text-(--color-fg) font-semibold text-base sm:text-lg mb-2">{title}</h2>
      <div className="space-y-2">{children}</div>
    </section>
  )
}
