document.getElementById('donateButton').addEventListener('click', function() {
  const donateUrl = this.getAttribute('data-url');
  window.location.href = donateUrl;
});


document.getElementById('requestButton').addEventListener('click', function() {
  const requestUrl = this.getAttribute('data-url');
  window.location.href = requestUrl;
});

// Get a reference to the share button
const shareButton = document.getElementById('shareButton');

// Get a reference to the share content
const shareContent = document.getElementById('shareContent');

// Add a click event listener to the share button
shareButton.addEventListener('click', async () => {
  try {
    // Check if the navigator.share method is available
    if (navigator.share) {
      // Use navigator.share to trigger the native share dialog
      await navigator.share({
        title: shareContent.querySelector('h2').innerText, // Title of the shared content
        text: shareContent.querySelector('p').innerText,   // Text content to share
        url: window.location.href                           // URL of the shared content
      });
      console.log('Shared successfully!');
    } else {
      // Fallback for browsers that do not support navigator.share
      alert('Sharing is not supported in your browser.');
    }
  } catch (error) {
    console.error('Error sharing:', error);
    // Handle errors while sharing
  }
});

// Get location button function for donation and request forms
function getLocation(formId) {
  if (navigator.geolocation) {
      navigator.geolocation.getCurrentPosition(
          position => {
              const locationField = document.getElementById(`${formId}-location`);
              locationField.value = `${position.coords.latitude}, ${position.coords.longitude}`;
          },
          error => {
              alert("Unable to retrieve your location. Please try again.");
          }
      );
  } else {
      alert("Geolocation is not supported by this browser.");
  }
}

// Show additional input field when "Other" is selected in the dropdown
document.getElementById('medicine').addEventListener('change', function() {
  const otherMedicineField = document.getElementById('otherMedicine');
  if (this.value === 'other') {
    otherMedicineField.style.display = 'block';
  } else {
    otherMedicineField.style.display = 'none';
  }
});

// Help modal functions
function showHelp(type) {
  var helpContent = document.getElementById('helpContent');
  if (helpContent) {
    if (type === 'phone') {
      helpContent.innerHTML = '<p>Contact us via phone at:</p><p>Phone: <a href="tel:+91-9422188681">+91-9422188681</a></p>';
    } else if (type === 'email') {
      helpContent.innerHTML = '<p>Contact us via email at:</p><p>Email: <a href="mailto:givehubdonations@gmail.com">givehubdonations@gmail.com</a></p>';
    } else if (type === 'location') {
      helpContent.innerHTML = '<p>Our location is:</p><p>xyz 123 Nagar, Jalgaon, Maharashtra, India 425001.</p>';
    }
    document.getElementById('helpModal').style.display = 'block';
  }
}

function closeHelp() {
  document.getElementById('helpModal').style.display = 'none';
}

