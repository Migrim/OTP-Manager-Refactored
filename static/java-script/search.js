let searchData = [];
let selectedIndex = -1;
let activeSuggestions = [];
let animationFrame = null;

document.addEventListener("DOMContentLoaded", () => {
    const input = document.getElementById('search-field');
    const list = document.getElementById('search-suggestions');
    const searchModal = document.getElementById('search-modal');

    if (!input || !list || !searchModal) return;

    fetch('/api/secrets')
        .then(res => res.json())
        .then(data => searchData = data);

    function clearSearch() {
        input.value = '';
        list.innerHTML = '';
        list.classList.add('hidden');
        selectedIndex = -1;
        activeSuggestions = [];
    }

    function copySafe(t){
        if (window.isSecureContext && navigator.clipboard && navigator.clipboard.writeText) {
          return navigator.clipboard.writeText(t);
        }
        return new Promise((resolve,reject)=>{
          const el=document.createElement('textarea');
          el.value=t;
          el.setAttribute('readonly','');
          el.style.position='fixed';
          el.style.opacity='0';
          document.body.appendChild(el);
          el.select();
          try{ document.execCommand('copy') ? resolve() : reject(); }catch(e){ reject(e); }
          document.body.removeChild(el);
        });
    }

    function openSearchModal() {
        searchModal.classList.add('active');
        clearSearch();
        setTimeout(() => input.focus(), 50);
        startAnimationLoop();
    }

    function closeSearchModal() {
        searchModal.classList.remove('active');
        cancelAnimationFrame(animationFrame);
        animationFrame = null;
    }

    async function handleSearch(value) {
        list.innerHTML = '';
        list.classList.remove('hidden');
        selectedIndex = -1;
        activeSuggestions = [];
    
        if (!value) {
            list.classList.add('hidden');
            return;
        }
    
        value = value.toLowerCase();
    
        const companyMap = new Map();
        const matches = [];
    
        for (const entry of searchData) {
            const nameMatch = entry.name && entry.name.toLowerCase().includes(value);
            const emailMatch = entry.email && entry.email.toLowerCase().includes(value);
            const companyMatch = entry.company_name && entry.company_name.toLowerCase().includes(value);
    
            if (companyMatch && !companyMap.has(entry.company_name)) {
                companyMap.set(entry.company_name, entry);
            }
    
            if (nameMatch || emailMatch || companyMatch) {
                matches.push(entry);
            }
        }
    
        for (const [company, entry] of companyMap.entries()) {
            const li = document.createElement('li');
            li.dataset.query = company;
    
            li.innerHTML = `
                <div class="suggestion-content">
                    <div class="suggestion-info">
                        <div class="suggestion-main">
                            <span class="material-symbols-outlined" style="font-size:18px;margin-right:6px;">business</span>
                            ${company}
                        </div>
                    </div>
                </div>
            `;
    
            li.addEventListener('click', () => {
                window.location.href = `/search.html?q=${encodeURIComponent(company)}`;
            });
    
            list.appendChild(li);
        }
    
        const individualEntries = matches.filter(e => e.name || e.email).slice(0, 8);
    
        for (const item of individualEntries) {
            const li = document.createElement('li');
            li.dataset.query = item.name || item.company_name;
    
            const res = await fetch(`/api/secrets/${item.id}`);
            const data = await res.json();
    
            li.dataset.code = data.current_code;
    
            const codeDigits = [...data.current_code].map((d, i) =>
                `<span class="digit" style="animation-delay: ${i * 40}ms">${d}</span>`
            ).join('');
    
            li.innerHTML = `
                <div class="suggestion-content">
                    <div class="suggestion-info">
                        <div class="suggestion-main">${item.company_name || 'Unknown'} - ${item.name}</div>
                        <div class="suggestion-email">${item.email || ''}</div>
                    </div>
                    <div class="suggestion-code">
                        <span class="code-text">${codeDigits}</span>
                        <svg class="countdown-circle" width="24" height="24" viewBox="0 0 36 36">
                            <circle class="circle-bg" cx="18" cy="18" r="16" />
                            <circle class="circle-fg" cx="18" cy="18" r="16" stroke-dasharray="100" stroke-dashoffset="0" />
                        </svg>
                    </div>
                </div>
            `;
    
            li.addEventListener('click', () => {
                window.location.href = `/search.html?q=${encodeURIComponent(item.name)}`;
            });
    
            li.addEventListener('mouseover', () => {
                selectedIndex = -1;
                list.querySelectorAll('li').forEach(el => el.classList.remove('active'));
                li.classList.add('active');
            });
    
            list.appendChild(li);
    
            activeSuggestions.push({
                id: item.id,
                li,
                circle: li.querySelector('.circle-fg'),
                codeEl: li.querySelector('.code-text'),
                secondsLeft: data.seconds_remaining,
                lastTimestamp: performance.now()
            });
        }
    
        if (list.children.length === 0) {
            const li = document.createElement('li');
            li.classList.add('no-results');
            li.dataset.query = value;
            li.innerHTML = `
                <div class="suggestion-content no-results-content">
                    <span class="material-symbols-outlined no-results-icon">search_off</span>
                    <div class="suggestion-info">
                        <div class="suggestion-main">No results</div>
                    </div>
                </div>
            `;
            list.appendChild(li);
            list.classList.remove('hidden');
        } else {
            list.classList.remove('hidden');
        }
    }

    function startAnimationLoop() {
        function loop() {
            const now = performance.now();

            for (const suggestion of activeSuggestions) {
                const elapsed = (now - suggestion.lastTimestamp) / 1000;
                const remaining = Math.max(suggestion.secondsLeft - elapsed, 0);
                const percent = (remaining / 30) * 100;

                if (suggestion.circle) {
                    suggestion.circle.style.strokeDashoffset = 100 - percent;
                }

                if (remaining <= 0) {
                    refreshCode(suggestion);
                }
            }

            animationFrame = requestAnimationFrame(loop);
        }

        if (!animationFrame) animationFrame = requestAnimationFrame(loop);
    }

    async function refreshCode(suggestion) {
        const res = await fetch(`/api/secrets/${suggestion.id}`);
        const updated = await res.json();

        suggestion.secondsLeft = updated.seconds_remaining;
        suggestion.lastTimestamp = performance.now();

        const newCode = [...updated.current_code].map((d, i) =>
            `<span class="digit" style="animation-delay: ${i * 40}ms">${d}</span>`
        ).join('');

        suggestion.codeEl.innerHTML = newCode;
        suggestion.li.dataset.code = updated.current_code;
    }

    let debounceTimer;
    input.addEventListener('input', () => {
        const value = input.value.toLowerCase().trim();
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(() => {
            handleSearch(value);
        }, 120);
    });

    input.addEventListener('keydown', (e) => {
        const items = list.querySelectorAll('li');
        if (items.length === 0) return;
    
        if (e.key === 'ArrowDown' || (e.key === 'Tab' && !e.shiftKey)) {
            e.preventDefault();
            selectedIndex = (selectedIndex + 1) % items.length;
            scrollToActive();
        } else if (e.key === 'ArrowUp' || (e.key === 'Tab' && e.shiftKey)) {
            e.preventDefault();
            selectedIndex = (selectedIndex - 1 + items.length) % items.length;
            scrollToActive();
        } else if (e.key === 'Enter') {
            e.preventDefault();
            const selected = items[selectedIndex];
            const query = selected ? selected.dataset.query : input.value;
    
            const value = query.toLowerCase().trim();
            const matches = searchData.filter(entry => {
                const nameMatch = entry.name && entry.name.toLowerCase().includes(value);
                const emailMatch = entry.email && entry.email.toLowerCase().includes(value);
                const companyMatch = entry.company_name && entry.company_name.toLowerCase().includes(value);
                return nameMatch || emailMatch || companyMatch;
            });
    
            if (matches.length > 50) {
                const proceed = confirm(`This search has ${matches.length} results.\nStaying on the results page may cause high system usage.\n\nContinue?`);
                if (!proceed) return;
            }
    
            window.location.href = `/search.html?q=${encodeURIComponent(query)}`;
        }
    
        list.querySelectorAll('li').forEach(el => el.classList.remove('active'));
        items.forEach((el, i) => {
            el.classList.toggle('active', i === selectedIndex);
        });
    });

    function scrollToActive() {
        const items = list.querySelectorAll('li');
        if (selectedIndex >= 0 && selectedIndex < items.length) {
            const el = items[selectedIndex];
            el.scrollIntoView({ block: 'nearest' });
        }
    }

    document.addEventListener('keydown', (e) => {
        if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
            e.preventDefault();
            openSearchModal();
        }

        if (searchModal.classList.contains('active') && e.key === 'Escape') {
            e.preventDefault();
            closeSearchModal();
        }

        if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'c') {
            if (!searchModal.classList.contains('active')) return;
            e.preventDefault();
            e.stopPropagation();
        
            const items = list.querySelectorAll('li');
            if (selectedIndex >= 0 && selectedIndex < items.length) {
                const code = items[selectedIndex].dataset.code;
                if (!code) return;
        
                if (navigator.clipboard && navigator.clipboard.writeText) {
                    navigator.clipboard.writeText(code)
                        .then(() => alert(`Copied OTP: ${code}`))
                        .catch(() => {
                            const el = document.createElement('textarea');
                            el.value = code;
                            el.setAttribute('readonly', '');
                            el.style.position = 'absolute';
                            el.style.left = '-9999px';
                            document.body.appendChild(el);
                            el.select();
                            document.execCommand('copy');
                            document.body.removeChild(el);
                            alert(`Copied OTP: ${code}`);
                        });
                } else {
                    const el = document.createElement('textarea');
                    el.value = code;
                    el.setAttribute('readonly', '');
                    el.style.position = 'absolute';
                    el.style.left = '-9999px';
                    document.body.appendChild(el);
                    el.select();
                    document.execCommand('copy');
                    document.body.removeChild(el);
                    alert(`Copied OTP: ${code}`);
                }
            }
        }
    });

    searchModal.addEventListener('click', (e) => {
        if (e.target === searchModal) {
            closeSearchModal();
        }
    });
});