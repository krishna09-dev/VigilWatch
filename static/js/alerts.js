// Home page file scanning script with modal popup for scan results

const dragDropArea = document.getElementById('dragDropArea');
const fileInput = document.getElementById('fileInput');
const uploadBtn = document.getElementById('uploadBtn');
const scanStatus = document.getElementById('scanStatus');
let selectedFile = null;

console.log("dragDropArea element:", dragDropArea);

dragDropArea.addEventListener('dragover', (e) => {
  e.preventDefault();
  dragDropArea.classList.add('hover');
});

dragDropArea.addEventListener('dragleave', (e) => {
  e.preventDefault();
  dragDropArea.classList.remove('hover');
});

dragDropArea.addEventListener('drop', (e) => {
  e.preventDefault();
  dragDropArea.classList.remove('hover');
  const files = e.dataTransfer.files;
  console.log("Dropped files:", files);
  if (files.length > 0) {
    selectedFile = files[0];
    dragDropArea.textContent = `Selected file: ${selectedFile.name}`;
    uploadBtn.style.display = 'inline-block';
    scanStatus.textContent = "";
  }
});

dragDropArea.addEventListener('click', () => {
  fileInput.click();
});

fileInput.addEventListener('change', (e) => {
  if (e.target.files.length > 0) {
    selectedFile = e.target.files[0];
    dragDropArea.textContent = `Selected file: ${selectedFile.name}`;
    uploadBtn.style.display = 'inline-block';
    scanStatus.textContent = "";
    console.log("File selected via input:", selectedFile);
  }
});

uploadBtn.addEventListener('click', () => {
  if (!selectedFile) return;
  // Show progress message
  scanStatus.textContent = "Scanning file...";
  uploadBtn.disabled = true;
  const formData = new FormData();
  formData.append('user', 'test_user');  // for demo purposes
  formData.append('upload_file', selectedFile);
  
  fetch('/upload', {
    method: 'POST',
    body: formData
  })
  .then(response => response.json())
  .then(data => {
    uploadBtn.disabled = false;
    scanStatus.textContent = "Scan completed.";
    // Show modal with scan result
    if (data.status === "alert") {
      showScanModal("Scan Result", data.message);
    } else if (data.status === "success") {
      showScanModal("Scan Result", data.message);
    } else {
      showScanModal("Scan Result", "Unexpected response.");
    }
  })
  .catch(err => {
    console.error('Error uploading file:', err);
    uploadBtn.disabled = false;
    scanStatus.textContent = "Error scanning file.";
    showScanModal("Scan Error", "There was an error scanning your file.");
  });
});

// Modal functions
function showScanModal(title, message) {
  document.getElementById("modalTitle").textContent = title;
  document.getElementById("modalMessage").textContent = message;
  document.getElementById("scanModal").style.display = "block";
}

document.getElementById("closeScanModal").addEventListener("click", () => {
  document.getElementById("scanModal").style.display = "none";
});

document.getElementById("modalOk").addEventListener("click", () => {
  document.getElementById("scanModal").style.display = "none";
});
