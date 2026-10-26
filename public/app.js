
const $ = (selector) => document.querySelector(selector);

let authMode = "login";
let currentLanguage = "en";

const translations = {
  en: {
    navHome: "Home", navFeatures: "Features", navLabs: "Security Lab",
    signIn: "Sign in", createAccount: "Create account",
    eyebrow: "YOUR WEB SECURITY TRAINING GROUND",
    heroTitle: 'Think like an attacker.<br><span class="green">Build like a defender.</span>',
    heroDesc: "Learn web security in a practical lab. Understand vulnerabilities, test your defenses, and build safer applications.",
    getStarted: "Get started", exploreLabs: "Explore labs ↓",
    localNote: "Local learning environment · Practice responsibly",
    systemReady: "SYSTEM READY", learningMode: "LEARNING MODE",
    whyTitle: "WHY SECUREWEB LAB", featuresTitle: "Learn security by doing.",
    featuresDesc: "Build real skills with guided, hands-on learning.",
    feature1Title: "Hands-on Labs", feature1Desc: "Understand common web vulnerabilities in a controlled training environment.",
    feature2Title: "Secure Authentication", feature2Desc: "Explore password hashing, sessions, and access control.",
    feature3Title: "Track Progress", feature3Desc: "Use your dashboard to follow your learning journey.",
    labEyebrow: "PRACTICE ZONE", labTitle: "Explore the Security Lab.",
    labDesc: "Start with the concepts behind real-world web application security.",
    xssDesc: "Learn how untrusted input can become executable browser content and how output encoding helps prevent it.",
    sqlDesc: "Understand unsafe database queries and how parameterized queries reduce injection risks.",
    accessTitle: "Access Control", accessDesc: "Explore authentication, authorization, and server-side permission checks.",
    secureTitle: "Secure Coding", secureDesc: "Practice validation, safe error handling, and security headers.",
    memberArea: "MEMBER AREA", welcomeBack: "Welcome back.",
    loginDesc: "Sign in to access your learning dashboard.",
    usernameOrEmail: "Username or email", email: "Email", password: "Password",
    passwordHint: "Use 8–72 characters.", yourDashboard: "YOUR DASHBOARD",
    welcome: "Welcome,", dashboardDesc: "Your security learning journey starts here.",
    availableLabs: "Available labs", completedLabs: "Completed", accountRole: "Account role",
    logout: "Log out", footerText: "Learn ethically. Test locally. Build securely."
  },
  ar: {
    navHome: "الرئيسية", navFeatures: "المميزات", navLabs: "معمل الأمن",
    signIn: "تسجيل الدخول", createAccount: "إنشاء حساب",
    eyebrow: "بيئة تدريب أمن تطبيقات الويب",
    heroTitle: 'فكّر كمختبر اختراق.<br><span class="green">وابنِ كمدافع.</span>',
    heroDesc: "اتعلم أمن الويب عمليًا، وافهم الثغرات واختبر وسائل الحماية وابنِ تطبيقات أكثر أمانًا.",
    getStarted: "ابدأ الآن", exploreLabs: "استكشف المعمل ↓",
    localNote: "بيئة تدريب محلية · استخدم المهارات بمسؤولية",
    systemReady: "النظام جاهز", learningMode: "وضع التعلم",
    whyTitle: "لماذا SecureWeb Lab؟", featuresTitle: "اتعلم الأمن بالتطبيق.",
    featuresDesc: "طوّر مهارات عملية من خلال تدريبات موجهة.",
    feature1Title: "تدريبات عملية", feature1Desc: "افهم أشهر ثغرات الويب داخل بيئة تدريب آمنة ومحددة.",
    feature2Title: "تسجيل دخول آمن", feature2Desc: "اتعلم تشفير كلمات المرور والجلسات والتحكم في الصلاحيات.",
    feature3Title: "تابع تقدمك", feature3Desc: "استخدم لوحة التحكم لمتابعة رحلتك التعليمية.",
    labEyebrow: "منطقة التدريب", labTitle: "استكشف معمل الأمن.",
    labDesc: "ابدأ بفهم المفاهيم الأساسية لأمن تطبيقات الويب.",
    xssDesc: "افهم كيف يمكن أن يتحول الإدخال غير الموثوق إلى محتوى ينفذه المتصفح، وكيف يمنع الترميز ذلك.",
    sqlDesc: "افهم استعلامات قواعد البيانات غير الآمنة وكيف تقلل الاستعلامات المجهزة مخاطر الحقن.",
    accessTitle: "التحكم في الصلاحيات", accessDesc: "تعلّم المصادقة والتفويض والتحقق من الصلاحيات على الخادم.",
    secureTitle: "كتابة كود آمن", secureDesc: "تدرّب على التحقق من المدخلات ومعالجة الأخطاء وترويسات الحماية.",
    memberArea: "منطقة الأعضاء", welcomeBack: "أهلًا بعودتك.",
    loginDesc: "سجّل الدخول للوصول إلى لوحة التعلم.",
    usernameOrEmail: "اسم المستخدم أو البريد", email: "البريد الإلكتروني", password: "كلمة المرور",
    passwordHint: "استخدم من 8 إلى 72 حرفًا.", yourDashboard: "لوحة التحكم",
    welcome: "أهلًا،", dashboardDesc: "رحلتك لتعلم أمن المعلومات تبدأ هنا.",
    availableLabs: "المعامل المتاحة", completedLabs: "المكتمل", accountRole: "نوع الحساب",
    logout: "تسجيل الخروج", footerText: "تعلّم بمسؤولية. اختبر محليًا. ابنِ بأمان."
  }
};

function setMessage(element, message, type = "") {
  element.textContent = message;
  element.className = `message ${type}`;
}

function setMode(mode) {
  authMode = mode;
  $("#loginTab").classList.toggle("active", mode === "login");
  $("#registerTab").classList.toggle("active", mode === "register");
  $("#emailGroup").hidden = mode !== "register";
  $("#email").required = mode === "register";
  $("#passwordHint").hidden = mode !== "register";
  $("#authTitle").textContent = mode === "login"
    ? (currentLanguage === "ar" ? "أهلًا بعودتك." : "Welcome back.")
    : (currentLanguage === "ar" ? "أنشئ حسابك." : "Create your account.");
  $("#authSubtitle").textContent = mode === "login"
    ? translations[currentLanguage].loginDesc
    : (currentLanguage === "ar" ? "ابدأ رحلتك في تعلم أمن الويب." : "Create an account to start learning.");
  $("#submitAuth").textContent = translations[currentLanguage][mode === "login" ? "signIn" : "createAccount"];
  $("#password").autocomplete = mode === "login" ? "current-password" : "new-password";
  setMessage($("#authMessage"), "");
}

function setLanguage(language) {
  currentLanguage = language;
  document.documentElement.lang = language;
  document.documentElement.dir = language === "ar" ? "rtl" : "ltr";
  document.body.dir = document.documentElement.dir;
  $("#langBtn").textContent = language === "ar" ? "English" : "عربي";

  document.querySelectorAll("[data-i18n]").forEach((element) => {
    const key = element.dataset.i18n;
    const translated = translations[language][key];
    if (translated !== undefined) element.innerHTML = translated;
  });

  setMode(authMode);
}

async function api(url, options = {}) {
  const response = await fetch(url, {
    credentials: "same-origin",
    ...options,
    headers: {
      ...(options.body ? { "Content-Type": "application/json" } : {}),
      ...(options.headers || {})
    }
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || "Request failed.");
  return data;
}

function showDashboard(user, stats = null) {
  $("#authCard").hidden = true;
  $("#dashboard").hidden = false;
  $("#dashUsername").textContent = user.username;
  $("#statRole").textContent = user.role;
  if (stats) {
    $("#statLabs").textContent = stats.labs;
    $("#statCompleted").textContent = stats.completed;
  }
  $("#navLogin").textContent = currentLanguage === "ar" ? "لوحة التحكم" : "Dashboard";
}

function showAuth() {
  $("#dashboard").hidden = true;
  $("#authCard").hidden = false;
  $("#navLogin").textContent = translations[currentLanguage].signIn;
}

$("#loginTab").addEventListener("click", () => setMode("login"));
$("#registerTab").addEventListener("click", () => setMode("register"));

$("#langBtn").addEventListener("click", () => {
  setLanguage(currentLanguage === "en" ? "ar" : "en");
});

$("#navLogin").addEventListener("click", () => {
  if ($("#dashboard").hidden) {
    $("#account").scrollIntoView({ behavior: "smooth" });
  } else {
    $("#dashboard").scrollIntoView({ behavior: "smooth" });
  }
});

$("#getStarted").addEventListener("click", () => {
  $("#account").scrollIntoView({ behavior: "smooth" });
});

$("#authForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const username = $("#username").value.trim();
  const password = $("#password").value;
  const payload = { username, password };

  if (authMode === "register") {
    payload.email = $("#email").value.trim();
  }

  const endpoint = authMode === "login"
    ? "/api/auth/login"
    : "/api/auth/register";

  const button = $("#submitAuth");
  button.disabled = true;
  setMessage($("#authMessage"), currentLanguage === "ar" ? "جارٍ المعالجة..." : "Please wait...");

  try {
    const result = await api(endpoint, {
      method: "POST",
      body: JSON.stringify(payload)
    });
    const dashboard = await api("/api/dashboard");
    showDashboard(result.user, dashboard.stats);
    $("#authForm").reset();
    $("#account").scrollIntoView({ behavior: "smooth" });
  } catch (error) {
    setMessage($("#authMessage"), error.message, "error");
  } finally {
    button.disabled = false;
  }
});

$("#logoutBtn").addEventListener("click", async () => {
  try {
    await api("/api/auth/logout", { method: "POST" });
    showAuth();
    setMode("login");
    setMessage($("#authMessage"),
      currentLanguage === "ar" ? "تم تسجيل الخروج بنجاح." : "Signed out successfully.",
      "success"
    );
  } catch (error) {
    setMessage($("#dashMessage"), error.message, "error");
  }
});

async function initialize() {
  setLanguage("en");
  setMode("login");
  try {
    const result = await api("/api/auth/me");
    if (result.user) {
      const dashboard = await api("/api/dashboard");
      showDashboard(result.user, dashboard.stats);
    }
  } catch (error) {
    console.error("Could not restore session:", error.message);
  }
}

initialize();
