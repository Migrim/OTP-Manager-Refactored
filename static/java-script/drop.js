document.addEventListener("DOMContentLoaded", () => {
    const companyDropdown = document.getElementById("companyDropdown");
    let companies = [];

    if (!companyDropdown) return;

    async function loadCompanies() {
        try {
            const res = await fetch("/companies/json");
            if (!res.ok) throw new Error("Failed to fetch companies");
            companies = await res.json();
            populateDropdown(companies);
        } catch (e) {
            console.error("Could not load companies:", e);
            if (typeof showToast === "function") {
                showToast("Could not load companies", "error");
            }
        }
    }

    function populateDropdown(list) {
        companyDropdown.innerHTML = '<option value="">Select Company...</option>';
        list.forEach(c => {
            const opt = document.createElement("option");
            opt.value = c.name;  
            opt.textContent = c.name;
            companyDropdown.appendChild(opt);
        });
    }

    companyDropdown.addEventListener("change", () => {
        const selectedCompany = companyDropdown.value;
        if (selectedCompany) {
            const query = encodeURIComponent(selectedCompany);
            window.location.href = `/search.html?q=${query}`;
        }
    });

    loadCompanies();
});