/* table.js — sortable headers + per-column filter row.
   Ported from pi-vpn-pooler (opt-in via `.tbl[data-sortable="1"]`,
   `.tbl[data-filterable="1"]`). */
(function () {
  'use strict';

  function cmpFor(type) {
    if (type === 'num') {
      return function (a, b) { return parseFloat(a) - parseFloat(b); };
    }
    return function (a, b) { return String(a).localeCompare(String(b)); };
  }

  function getVal(tr, key) {
    if (tr.dataset[key] !== undefined) return tr.dataset[key];
    const table = tr.closest('table');
    if (!table) return '';
    const ths = table.tHead.rows[0].cells;
    for (let i = 0; i < ths.length; i++) {
      if (ths[i].dataset.key === key) {
        return tr.cells[i] ? tr.cells[i].textContent.trim() : '';
      }
    }
    return '';
  }

  function makeSortable(table) {
    const ths = table.querySelectorAll('thead th.sortable');
    let current = null;
    ths.forEach(function (th) {
      th.addEventListener('click', function () {
        const key = th.dataset.key;
        const type = th.dataset.type || 'str';
        if (!current || current.key !== key) {
          current = { key: key, dir: 'asc', type: type };
        } else if (current.dir === 'asc') {
          current.dir = 'desc';
        } else {
          current = null;
        }
        ths.forEach(function (h) {
          h.classList.remove('sorted');
          const si = h.querySelector('.sort-ico');
          if (si) si.textContent = '↕';
        });
        if (current) {
          th.classList.add('sorted');
          const si = th.querySelector('.sort-ico');
          if (si) si.textContent = current.dir === 'asc' ? '↑' : '↓';
          const rows = Array.from(table.tBodies[0].rows);
          const compare = cmpFor(type);
          rows.sort(function (a, b) {
            const r = compare(getVal(a, key), getVal(b, key));
            return current.dir === 'asc' ? r : -r;
          });
          const frag = document.createDocumentFragment();
          rows.forEach(function (r) { frag.appendChild(r); });
          table.tBodies[0].appendChild(frag);
        }
      });
    });
  }

  function makeFilterable(table) {
    const inputs = table.querySelectorAll('.filter-row input[data-filter-col]');
    inputs.forEach(function (inp) {
      inp.addEventListener('input', function () { apply(table); });
    });
    const counter = document.querySelector('[data-table-counter]');

    function apply(tbl) {
      const filters = {};
      tbl.querySelectorAll('.filter-row input[data-filter-col]').forEach(function (i) {
        const col = parseInt(i.dataset.filterCol, 10);
        const val = i.value.toLowerCase().trim();
        if (val) filters[col] = val;
      });
      const rows = tbl.tBodies[0].rows;
      let shown = 0, total = 0;
      for (let r = 0; r < rows.length; r++) {
        const tr = rows[r];
        total++;
        let match = true;
        for (const col in filters) {
          const cell = tr.cells[col];
          if (!cell || cell.textContent.toLowerCase().indexOf(filters[col]) === -1) {
            match = false; break;
          }
        }
        tr.style.display = match ? '' : 'none';
        if (match) shown++;
      }
      if (counter) {
        const [a, b] = [String(shown), String(total)];
        counter.textContent = counter.textContent.replace(/\d+/g, function (s, i, whole) {
          return i === whole.indexOf(/\d/) ? a : b;
        });
      }
    }
  }

  document.querySelectorAll('table.tbl[data-sortable="1"]').forEach(makeSortable);
  document.querySelectorAll('table.tbl[data-filterable="1"]').forEach(makeFilterable);
})();
