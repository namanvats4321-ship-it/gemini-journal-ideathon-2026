(function () {
  "use strict";

  const entry = document.getElementById("entry");
  const mirror = document.getElementById("mirror");
  const reflectButton = document.getElementById("reflect");

  if (!entry) {
    console.warn("Journal functionality: #entry not found.");
    return;
  }

  /* =========================
     API HELPER
     ========================= */

  async function api(url, options = {}) {
    const response = await fetch(url, {
      credentials: "include",
      ...options,
      headers: {
        "Content-Type": "application/json",
        ...(options.headers || {})
      }
    });

    let data = {};
    try {
      data = await response.json();
    } catch (_) {}

    if (!response.ok) {
      throw new Error(
        data.error ||
        data.message ||
        `Request failed (${response.status})`
      );
    }

    return data;
  }

  /* =========================
     PRIVACY SHIELD PREVIEW
     ========================= */

  let previewTimer = null;

  async function updateProtectedView() {
    const text = entry.value;

    if (!mirror) return;

    if (!text.trim()) {
      mirror.textContent =
        "Your protected text will appear here as you write.";
      mirror.classList.add("empty");
      return;
    }

    try {
      const preview = await api("/api/preview", {
        method: "POST",
        body: JSON.stringify({ text })
      });

      const protectedText =
        preview.redacted ??
        preview.protected_text ??
        preview.redacted_text ??
        preview.text ??
        text;

      mirror.textContent = protectedText;
      mirror.classList.remove("empty");

      window.lastProtectedJournalText = protectedText;

    } catch (error) {
      console.error("Privacy Shield preview failed:", error);

      mirror.textContent =
        "Protected preview temporarily unavailable.";
      mirror.classList.remove("empty");
    }
  }

  entry.addEventListener("input", function () {
    clearTimeout(previewTimer);

    previewTimer = setTimeout(updateProtectedView, 350);
  });

  /* =========================
     WRITE & REFLECT
     ========================= */

  if (reflectButton) {
    reflectButton.addEventListener("click", async function () {
      const text = entry.value.trim();

      if (!text) {
        entry.focus();
        return;
      }

      const originalText = reflectButton.textContent;

      try {
        reflectButton.disabled = true;
        reflectButton.setAttribute("aria-busy", "true");
        reflectButton.textContent = "Protecting your reflection…";

        const preview = await api("/api/preview", {
          method: "POST",
          body: JSON.stringify({ text })
        });

        const protectedText =
          preview.redacted ??
          preview.protected_text ??
          preview.redacted_text ??
          preview.text ??
          text;

        if (mirror) {
          mirror.textContent = protectedText;
          mirror.classList.remove("empty");
        }

        window.lastProtectedJournalText = protectedText;

        reflectButton.textContent = "Reflecting with Gemini…";

        const reflection = await api("/api/reflect", {
          method: "POST",
          body: JSON.stringify({
            text: protectedText
          })
        });

        window.lastJournalReflection = reflection;

        document.dispatchEvent(
          new CustomEvent("journal:reflection", {
            detail: {
              originalText: text,
              protectedText,
              reflection
            }
          })
        );

        console.log("Gemini reflection ready:", reflection);

        reflectButton.textContent = "Reflection ready";

        setTimeout(function () {
          reflectButton.textContent = originalText;
        }, 1800);

      } catch (error) {
        console.error("Journal reflection failed:", error);

        reflectButton.textContent = "Reflection failed";

        setTimeout(function () {
          reflectButton.textContent = originalText;
        }, 1800);

      } finally {
        reflectButton.disabled = false;
        reflectButton.removeAttribute("aria-busy");
      }
    });
  }

  /* =========================
     INITIAL STATE
     ========================= */

  updateProtectedView();

})();
