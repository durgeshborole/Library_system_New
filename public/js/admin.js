// admin.js

async function updateAutoExit() {
  const hour = document.getElementById("autoExitHour").value;
  const minute = document.getElementById("autoExitMinute").value;

  if (hour === "" || minute === "") {
    alert("Please fill both hour and minute.");
    return;
  }

  try {
    const res = await fetch("/admin/auto-exit", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ hour: parseInt(hour), minute: parseInt(minute) })
    });

    const result = await res.json();
    alert(result.message);
  } catch (err) {
    console.error("Auto-exit update failed:", err);
    alert("Failed to update auto-exit time.");
  }
}

async function forceExit() {
  if (!confirm("Are you sure you want to force exit all currently present users?")) return;

  const token = localStorage.getItem("authToken"); // Get it fresh
  if (!token) {
    alert("You are not logged in.");
    return;
  }

  try {
    const res = await fetch("/admin/force-exit", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${token}`,
      }
    });

    const result = await res.json();

    if (res.ok) {
      alert(`✅ ${result.modifiedCount} users were marked exited.`);
    } else {
      alert(`❌ Force exit failed: ${result.message || result.error}`);
    }

  } catch (err) {
    console.error("Force exit failed:", err);
    alert("Force exit failed.");
  }
}


async function exportLogs(type) {
  const endpoint = type === 'today' ? '/live-log' : '/all-logs';
  try {
    const res = await fetch(`${endpoint}`);
    const logs = await res.json();
    let csv = "Name,Department,Designation,Entry Time,Exit Time\n";
    logs.forEach(log => {
      csv += `${log.name},${log.department},${log.designation},${new Date(log.entryTime).toLocaleString()},${log.exitTime ? new Date(log.exitTime).toLocaleString() : "-"}\n`;
    });

    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `logs_${type}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  } catch (err) {
    console.error("Log export failed:", err);
    alert("Failed to export logs.");
  }
}

// Submit new library notice
async function submitNotice() {
  const noticeText = document.getElementById("noticeText").value.trim();
  const token = localStorage.getItem('authToken'); // Get the token

  if (!noticeText) {
    alert("Please enter a notice.");
    return;
  }
  if (!token) {
    alert("Authentication error. Please log in again.");
    return;
  }

  try {
    const res = await fetch("/admin/notices", {
      method: "POST",
      // ✅ ADDED: Headers with authentication token
      headers: { 
        "Content-Type": "application/json",
        "Authorization": `Bearer ${token}` 
      },
      body: JSON.stringify({ text: noticeText })
    });

    const data = await res.json();
    if (data.success) {
      alert("📢 Notice posted successfully.");
      document.getElementById("noticeText").value = "";
      loadAdminNotices(); // Refresh the list
    } else {
      alert("Failed to post notice: " + (data.message || 'Unknown error'));
    }
  } catch (err) {
    console.error("Notice post failed:", err);
    alert("Server error while posting notice.");
  }
}



async function loadAdminNotices() {
  const noticeList = document.getElementById("adminNoticeList");
  noticeList.innerHTML = "<li>Loading notices...</li>";

  try {
    const res = await fetch("/notices");
    const notices = await res.json();

    noticeList.innerHTML = "";

    if (notices.length === 0) {
      noticeList.innerHTML = "<li>No notices found.</li>";
    } else {
      notices.forEach(notice => {
        const li = document.createElement("li");
        li.textContent = notice.text;

        const deleteBtn = document.createElement("button");
        deleteBtn.textContent = "🗑️ Delete";
        deleteBtn.style.marginLeft = "10px";
        deleteBtn.onclick = () => deleteNotice(notice._id);

        li.appendChild(deleteBtn);
        noticeList.appendChild(li);
      });
    }
  } catch (err) {
    console.error("Failed to load notices:", err);
    noticeList.innerHTML = "<li>Failed to load notices.</li>";
  }
}

async function deleteNotice(id) {
  const token = localStorage.getItem('authToken'); // Get the token

  if (!confirm("Are you sure you want to delete this notice?")) return;
  if (!token) {
    alert("Authentication error. Please log in again.");
    return;
  }

  try {
    const res = await fetch(`/admin/notices/${id}`, {
      method: "DELETE",
      // ✅ ADDED: Headers with authentication token
      headers: {
        "Authorization": `Bearer ${token}`
      }
    });

    const data = await res.json();
    if (data.success) {
      alert("✅ Notice deleted successfully.");
      loadAdminNotices(); // Refresh list
    } else {
      alert("❌ Failed to delete notice.");
    }
  } catch (err) {
    console.error("Delete notice failed:", err);
    alert("❌ Server error during delete.");
  }
}

// Load notices automatically when Admin Panel opens
document.addEventListener("DOMContentLoaded", () => {
  loadAdminNotices();
});


async function uploadPhoto() {
  const barcode = document.getElementById('photoBarcode').value.trim();
  const fileInput = document.getElementById('photoFile');
  const file = fileInput.files[0];

  if (!barcode || !file) {
    alert('Please enter barcode and select a photo.');
    return;
  }

  const formData = new FormData();
  formData.append('barcode', barcode);
  formData.append('photo', file);

  try {
    const res = await fetch('/upload-photo', {
      method: 'POST',
      body: formData
    });

    const data = await res.json();
    if (data.success) {
      alert('✅ Photo uploaded successfully.');
      document.getElementById('photoBarcode').value = '';
      fileInput.value = '';
    } else {
      alert('❌ Upload failed.');
    }
  } catch (err) {
    console.error('Upload photo failed:', err);
    alert('❌ Server error.');
  }
}




async function bulkUploadPhotos() {
  const files = document.getElementById('bulkPhotoFiles').files;

  if (files.length === 0) {
    alert('Please select at least one file.');
    return;
  }

  const formData = new FormData();
  for (const file of files) {
    formData.append('photos', file); // "photos" must match server field
  }

  try {
    const res = await fetch('/bulk-upload-photos', {
      method: 'POST',
      body: formData
    });

    const data = await res.json();
    if (data.success) {
      alert(`✅ Successfully uploaded ${data.uploadedCount} photos.`);
      document.getElementById('bulkPhotoFiles').value = ''; // Clear input
    } else {
      alert('❌ Bulk upload failed.');
    }
  } catch (err) {
    console.error('Bulk upload failed:', err);
    alert('❌ Server error.');
  }
}

async function loadMonthlyAwards() {
  const resultBox = document.getElementById("awardResults");
  resultBox.innerHTML = "⏳ Loading...";

  try {
    const res = await fetch("/admin/monthly-awards");
    const data = await res.json();

    if (data.error) {
      resultBox.innerHTML = "❌ Failed to load awards.";
      return;
    }

    const student = data.topStudent
      ? `🏅 <b>${data.topStudent.name}</b> (Visits: ${data.topStudent.visits})`
      : "No student data.";

    const department = data.topDepartment
      ? `🏢 <b>${data.topDepartment.name}</b> (Visits: ${data.topDepartment.visits})`
      : "No department data.";

    resultBox.innerHTML = `
      <p><strong>Top Student:</strong> ${student}</p>
      <p><strong>Top Department:</strong> ${department}</p>
    `;
  } catch (err) {
    console.error("Error fetching awards:", err);
    resultBox.innerHTML = "❌ Server error.";
  }
}

async function addDepartment() {
  const code = document.getElementById("deptCode").value;
  const name = document.getElementById("deptName").value;
  await fetch("/api/departments", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ code, name })
  });
  alert("Department added");
}

async function addDesignation() {
  const code = document.getElementById("desgCode").value;
  const name = document.getElementById("desgName").value;
  await fetch("/api/designations", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ code, name })
  });
  alert("Designation added");
}

const deptForm = document.getElementById("addDeptForm");
deptForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const code = document.getElementById("deptCode").value;
  const name = document.getElementById("deptName").value;
  const res = await fetch("/api/departments", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ code, name })
  });
  const data = await res.json();
  alert(data.message);
  loadDepartments();
});

// Add Designation
const desgForm = document.getElementById("addDesgForm");
desgForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const code = document.getElementById("desgCode").value;
  const name = document.getElementById("desgName").value;
  const res = await fetch("/api/designations", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ code, name })
  });
  const data = await res.json();
  alert(data.message);
  loadDesignations();
});

// Load Departments
async function loadDepartments() {
  const res = await fetch("/api/departments");
  const depts = await res.json();
  const dropdown = document.getElementById("departmentDropdown");
  dropdown.innerHTML = "";
  depts.forEach(d => {
    const opt = document.createElement("option");
    opt.value = d.code;
    opt.textContent = d.name;
    dropdown.appendChild(opt);
  });
}

// Load Designations
async function loadDesignations() {
  const res = await fetch("/api/designations");
  const desgs = await res.json();
  const dropdown = document.getElementById("designationDropdown");
  dropdown.innerHTML = "";
  desgs.forEach(d => {
    const opt = document.createElement("option");
    opt.value = d.code;
    opt.textContent = d.name;
    dropdown.appendChild(opt);
  });
}

// Call these on page load
window.onload = () => {
  loadDepartments();
  loadDesignations();
};
