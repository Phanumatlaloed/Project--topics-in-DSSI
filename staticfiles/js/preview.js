
// Modal handling - Fixed flickering issues
document.addEventListener('DOMContentLoaded', function() {
    // Create a single modal instance for navigation
    let activeModal = null;
    let currentPostId = null;
    let currentIndex = 0;
    let totalItems = 0;
    
    // Handle clicks on media items
    document.querySelectorAll('.media-item').forEach(item => {
        item.addEventListener('click', function(e) {
            e.preventDefault();
            const targetId = this.getAttribute('data-bs-target');
            openMediaModal(targetId);
        });
    });
    
    // Handle clicks on gallery items
    document.querySelectorAll('.gallery-item').forEach(item => {
        item.addEventListener('click', function(e) {
            e.preventDefault();
            const modalId = this.getAttribute('data-media-id') || this.getAttribute('onclick').match(/'([^']+)'/)[1];
            openMediaModal(modalId);
        });
    });
    
    // Improved openMediaModal function
    window.openMediaModal = function(modalId) {
        // Extract post ID and item index from modalId
        const matches = modalId.match(/mediaModal-(\d+)-(\d+)/);
        if (matches) {
            currentPostId = matches[1];
            currentIndex = parseInt(matches[2]) - 1;
            
            // Count total items for this post
            const mediaItems = document.querySelectorAll(`[id^="mediaModal-${currentPostId}-"]`);
            totalItems = mediaItems.length;
            
            // If there's an active modal, hide it without animation
            if (activeModal) {
                const modalElement = document.getElementById(activeModal);
                if (modalElement) {
                    modalElement.classList.remove('show');
                    modalElement.style.display = 'none';
                }
            }
            
            // Show the new modal without flicker
            const targetModal = document.getElementById(modalId);
            if (targetModal) {
                // Setup navigation if multiple items
                setupModalNavigation(targetModal);
                
                // Show modal smoothly
                targetModal.style.display = 'block';
                setTimeout(() => {
                    targetModal.classList.add('show');
                }, 10);
                
                // Update active modal reference
                activeModal = modalId;
                
                // Add event listeners for keyboard navigation
                document.addEventListener('keydown', handleKeyNavigation);
            }
        }
    };
    
    // Setup modal navigation
    function setupModalNavigation(modal) {
        // Don't add navigation if already present or only one item
        if (modal.querySelector('.media-nav') || totalItems <= 1) {
            updateCounter(modal);
            return;
        }
        
        const modalBody = modal.querySelector('.modal-body');
        
        // Create navigation container
        const navContainer = document.createElement('div');
        navContainer.className = 'media-nav';
        
        // Previous button
        const prevBtn = document.createElement('button');
        prevBtn.className = 'nav-btn prev-btn';
        prevBtn.innerHTML = '<i class="fas fa-chevron-left"></i>';
        prevBtn.addEventListener('click', function(e) {
            e.stopPropagation();
            navigateMedia(-1);
        });
        
        // Next button
        const nextBtn = document.createElement('button');
        nextBtn.className = 'nav-btn next-btn';
        nextBtn.innerHTML = '<i class="fas fa-chevron-right"></i>';
        nextBtn.addEventListener('click', function(e) {
            e.stopPropagation();
            navigateMedia(1);
        });
        
        // Counter
        const counter = document.createElement('div');
        counter.className = 'media-counter';
        counter.textContent = `${currentIndex + 1} / ${totalItems}`;
        
        // Append elements
        navContainer.appendChild(prevBtn);
        navContainer.appendChild(counter);
        navContainer.appendChild(nextBtn);
        modalBody.appendChild(navContainer);
        
        // Add close button if not present
        if (!modal.querySelector('.close-button')) {
            const closeButton = document.createElement('button');
            closeButton.className = 'close-button';
            closeButton.innerHTML = '<i class="fas fa-times"></i>';
            closeButton.addEventListener('click', function() {
                closeModal(modal);
            });
            modalBody.appendChild(closeButton);
        }
    }
    
    // Update counter
    function updateCounter(modal) {
        const counter = modal.querySelector('.media-counter');
        if (counter) {
            counter.textContent = `${currentIndex + 1} / ${totalItems}`;
        }
    }
    
    // Media navigation function
    function navigateMedia(direction) {
        // Calculate new index with wrap-around
        let newIndex = currentIndex + direction;
        if (newIndex < 0) newIndex = totalItems - 1;
        if (newIndex >= totalItems) newIndex = 0;
        
        // Close current modal
        if (activeModal) {
            const modal = document.getElementById(activeModal);
            if (modal) {
                modal.classList.remove('show');
                modal.style.display = 'none';
            }
        }
        
        // Open new modal
        currentIndex = newIndex;
        const newModalId = `mediaModal-${currentPostId}-${newIndex + 1}`;
        
        // Show new modal without animation for smooth transition
        const newModal = document.getElementById(newModalId);
        if (newModal) {
            setupModalNavigation(newModal);
            newModal.style.display = 'block';
            setTimeout(() => {
                newModal.classList.add('show');
            }, 10);
            activeModal = newModalId;
        }
    }
    
    // Handle keyboard navigation
    function handleKeyNavigation(e) {
        if (!activeModal) return;
        
        switch(e.key) {
            case 'ArrowLeft':
                navigateMedia(-1);
                e.preventDefault();
                break;
            case 'ArrowRight':
                navigateMedia(1);
                e.preventDefault();
                break;
            case 'Escape':
                closeAllModals();
                e.preventDefault();
                break;
        }
    }
    
    // Close current modal
    function closeModal(modal) {
        if (modal) {
            modal.classList.remove('show');
            setTimeout(() => {
                modal.style.display = 'none';
            }, 300);
            activeModal = null;
            document.removeEventListener('keydown', handleKeyNavigation);
        }
    }
    
    // Close all modals
    function closeAllModals() {
        document.querySelectorAll('.modal.show').forEach(modal => {
            closeModal(modal);
        });
    }
    
    // Close modals when clicking backdrop
    document.addEventListener('click', function(e) {
        if (e.target.classList.contains('modal')) {
            closeAllModals();
        }
    });
    
    // Add ESC key handler for all modals
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') {
            closeAllModals();
        }
    });
    
    // Enhanced image preview for image uploads
    const postImages = document.getElementById('postImages');
    const imagePreview = document.getElementById('imagePreview');
    
    if (postImages && imagePreview) {
        postImages.addEventListener('change', function() {
            imagePreview.innerHTML = '';
            
            if (this.files && this.files.length > 0) {
                imagePreview.classList.add('d-flex', 'flex-wrap', 'gap-2');
                
                const fileCount = Math.min(this.files.length, 4);
                
                for (let i = 0; i < fileCount; i++) {
                    const reader = new FileReader();
                    reader.onload = function(e) {
                        const imgPreview = document.createElement('div');
                        imgPreview.className = 'preview-item position-relative';
                        imgPreview.innerHTML = `
                            <img src="${e.target.result}" class="img-thumbnail" style="width: 100px; height: 100px; object-fit: cover; border-radius: 8px;">
                            <button type="button" class="btn-close position-absolute top-0 end-0 bg-danger text-white" style="padding: 2px;"></button>
                        `;
                        imagePreview.appendChild(imgPreview);
                        
                        // Remove image on close button click
                        imgPreview.querySelector('.btn-close').addEventListener('click', function() {
                            imgPreview.remove();
                            // Update preview if all images are removed
                            if (imagePreview.children.length === 0) {
                                imagePreview.classList.remove('d-flex', 'flex-wrap', 'gap-2');
                            }
                        });
                    }
                    reader.readAsDataURL(this.files[i]);
                }
                
                if (this.files.length > 4) {
                    const moreIndicator = document.createElement('div');
                    moreIndicator.className = 'more-indicator bg-light rounded p-2 d-flex align-items-center justify-content-center';
                    moreIndicator.style.width = '100px';
                    moreIndicator.style.height = '100px';
                    moreIndicator.innerHTML = `<span>+${this.files.length - 4} เพิ่มเติม</span>`;
                    imagePreview.appendChild(moreIndicator);
                }
            }
        });
    }
    
    // Comment form functionality
    document.querySelectorAll('.comment-input').forEach(input => {
        input.addEventListener('input', function() {
            const submitBtn = this.closest('.comment-form').querySelector('.comment-submit');
            submitBtn.disabled = this.value.trim() === '';
        });
    });
});

// // เพิ่ม JavaScript เพื่อให้สามารถปิดโมดัลด้วยการคลิกที่พื้นหลัง
// document.addEventListener('DOMContentLoaded', function() {
//     // ปิดโมดัลเมื่อคลิกที่พื้นหลัง
//     document.addEventListener('click', function(event) {
//         // ตรวจสอบว่ามีโมดัลที่กำลังแสดงอยู่หรือไม่
//         const activeModal = document.querySelector('.modal.show');
//         if (activeModal) {
//             // ตรวจสอบว่าคลิกที่พื้นหลังหรือไม่ (ไม่ได้คลิกที่เนื้อหาของโมดัล)
//             if (event.target.classList.contains('modal')) {
//                 const modal = bootstrap.Modal.getInstance(activeModal);
//                 if (modal) {
//                     modal.hide();
//                 }
//             }
//         }
//     });

//     // เพิ่มปุ่มปิดในทุกๆ modal และให้สามารถกดปุ่ม ESC เพื่อปิดได้
//     const modals = document.querySelectorAll('.modal');
//     modals.forEach(modal => {
//         // เพิ่ม event listener สำหรับการกดปุ่ม ESC
//         modal.addEventListener('keydown', function(event) {
//             if (event.key === 'Escape') {
//                 const modalInstance = bootstrap.Modal.getInstance(modal);
//                 if (modalInstance) {
//                     modalInstance.hide();
//                 }
//             }
//         });
//     });

//     // เปลี่ยนการทำงานของฟังก์ชัน openMediaModal
//     window.openMediaModal = function(modalId) {
//         // ปิดโมดัลที่กำลังแสดงอยู่
//         const galleryModal = bootstrap.Modal.getInstance(document.querySelector('.modal.show'));
//         if (galleryModal) {
//             galleryModal.hide();
//         }
        
//         // แสดงโมดัลใหม่
//         setTimeout(() => {
//             const targetModal = document.getElementById(modalId);
//             if (targetModal) {
//                 const mediaModal = new bootstrap.Modal(targetModal);
//                 mediaModal.show();
                
//                 // เพิ่มปุ่มปิดถ้ายังไม่มี
//                 if (!targetModal.querySelector('.close-button')) {
//                     const modalBody = targetModal.querySelector('.modal-body');
//                     const closeButton = document.createElement('button');
//                     closeButton.className = 'close-button';
//                     closeButton.innerHTML = '<i class="fas fa-times"></i>';
//                     closeButton.setAttribute('data-bs-dismiss', 'modal');
//                     modalBody.appendChild(closeButton);
//                 }
//             }
//         }, 400);
//     };
// });
// // Media preview functionality
// document.addEventListener('DOMContentLoaded', function() {
//     // Preview images before upload
//     const postImages = document.getElementById('postImages');
//     const imagePreview = document.getElementById('imagePreview');
    
//     if (postImages && imagePreview) {
//         postImages.addEventListener('change', function() {
//             imagePreview.innerHTML = '';
            
//             if (this.files) {
//                 const fileCount = Math.min(this.files.length, 4);
//                 imagePreview.classList.add('d-flex', 'flex-wrap', 'gap-2');
                
//                 for (let i = 0; i < fileCount; i++) {
//                     const reader = new FileReader();
//                     reader.onload = function(e) {
//                         const imgPreview = document.createElement('div');
//                         imgPreview.className = 'preview-item position-relative';
//                         imgPreview.innerHTML = `
//                             <img src="${e.target.result}" class="img-thumbnail" style="width: 100px; height: 100px; object-fit: cover; border-radius: 8px;">
//                             <button type="button" class="btn-close position-absolute top-0 end-0 bg-danger text-white" style="padding: 2px;"></button>
//                         `;
//                         imagePreview.appendChild(imgPreview);
                        
//                         // Remove image on close button click
//                         imgPreview.querySelector('.btn-close').addEventListener('click', function() {
//                             imgPreview.remove();
//                         });
//                     }
//                     reader.readAsDataURL(this.files[i]);
//                 }
                
//                 if (this.files.length > 4) {
//                     const moreIndicator = document.createElement('div');
//                     moreIndicator.className = 'more-indicator bg-light rounded p-2 d-flex align-items-center justify-content-center';
//                     moreIndicator.style.width = '100px';
//                     moreIndicator.style.height = '100px';
//                     moreIndicator.innerHTML = `<span>+${this.files.length - 4} เพิ่มเติม</span>`;
//                     imagePreview.appendChild(moreIndicator);
//                 }
//             }
//         });
//     }
// });
// // Function to open individual media modals from the gallery
// function openMediaModal(modalId) {
//     // Hide the gallery modal
//     const galleryModal = bootstrap.Modal.getInstance(document.querySelector('.modal.show'));
//     if (galleryModal) {
//         galleryModal.hide();
//     }
    
//     // Show the individual media modal
//     setTimeout(() => {
//         const mediaModal = new bootstrap.Modal(document.getElementById(modalId));
//         mediaModal.show();
//     }, 400); // Small delay to allow the first modal to close
// }

// // Add navigation between media items
// document.addEventListener('DOMContentLoaded', function() {
//     // Setup media navigation for each post
//     const posts = document.querySelectorAll('.post');
    
//     posts.forEach(post => {
//         const postId = post.id.replace('post-', '');
//         const mediaModals = document.querySelectorAll(`[id^="mediaModal-${postId}-"]`);
        
//         if (mediaModals.length <= 1) return; // No need for navigation if there's only one media item
        
//         mediaModals.forEach((modal, index) => {
//             // Add navigation buttons if not already present
//             if (!modal.querySelector('.media-nav')) {
//                 const modalBody = modal.querySelector('.modal-body');
                
//                 // Create navigation container
//                 const navContainer = document.createElement('div');
//                 navContainer.className = 'media-nav';
                
//                 // Previous button
//                 const prevBtn = document.createElement('button');
//                 prevBtn.className = 'nav-btn prev-btn';
//                 prevBtn.innerHTML = '<i class="fas fa-chevron-left"></i>';
//                 prevBtn.addEventListener('click', function(e) {
//                     e.stopPropagation();
//                     navigateMedia(postId, index, -1, mediaModals.length);
//                 });
                
//                 // Next button
//                 const nextBtn = document.createElement('button');
//                 nextBtn.className = 'nav-btn next-btn';
//                 nextBtn.innerHTML = '<i class="fas fa-chevron-right"></i>';
//                 nextBtn.addEventListener('click', function(e) {
//                     e.stopPropagation();
//                     navigateMedia(postId, index, 1, mediaModals.length);
//                 });
                
//                 // Counter
//                 const counter = document.createElement('div');
//                 counter.className = 'media-counter';
//                 counter.textContent = `${index + 1} / ${mediaModals.length}`;
                
//                 // Append elements
//                 navContainer.appendChild(prevBtn);
//                 navContainer.appendChild(counter);
//                 navContainer.appendChild(nextBtn);
//                 modalBody.appendChild(navContainer);
//             }
//         });
//     });
//     // });

//     // Function to navigate between media items
//     function navigateMedia(postId, currentIndex, direction, totalItems) {
//         // Calculate the new index
//         let newIndex = currentIndex + direction;
        
//         // Handle wrap-around
//         if (newIndex < 0) newIndex = totalItems - 1;
//         if (newIndex >= totalItems) newIndex = 0;
        
//         // Hide current modal
//         const currentModal = bootstrap.Modal.getInstance(document.querySelector('.modal.show'));
//         if (currentModal) {
//             currentModal.hide();
//         }
        
//         // Show the new modal
//         setTimeout(() => {
//             const targetModalId = `mediaModal-${postId}-${newIndex + 1}`;
//             const targetModal = new bootstrap.Modal(document.getElementById(targetModalId));
//             targetModal.show();
//         }, 400);
//     }
// });
