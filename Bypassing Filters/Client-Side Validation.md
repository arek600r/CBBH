# Client-Side Validation – Key Notes for Pentesters

## What is Client-Side Validation?
- File type checks are done using JavaScript in the browser, before hitting the backend.
- E.g., upload forms only allow `.jpg`, `.png`, etc., and disable the upload button for other types.

## Why is it Weak?
- **Client-side validation is under the user's control.**
- Attackers can:
    - Modify or disable JS validation using browser dev tools.
    - Directly send crafted upload requests (e.g., via Burp Suite) and skip the frontend completely.

## Bypassing Client-Side Validation

### 1. Intercept & Modify Requests
- Use a proxy tool like **Burp Suite**:
    - Upload a legit file to capture the normal request.
    - Edit the request: change filename and file content (e.g., PHP web shell instead of an image).
    - If the backend doesn't re-validate, your payload will be accepted.

### 2. Tweak/Remove JS on the Fly
- Use browser dev tools (F12):
    - Find the file input and HTML (`accept=".jpg,.jpeg,.png"`, etc.).
    - Remove or modify validation attributes or change the JS function that blocks uploads.
    - Temporarily disable or change validation functions (`checkFile`).
    - Result: You can now select and upload your malicious file.

## Practical Example (TL;DR)
1. The upload form only allows images; you can’t select scripts via dialog.
2. However, you:
    - Edit the frontend (remove validation/checks), OR
    - Intercept the request with Burp, change the file to `shell.php` and its contents.
3. Submit the modified request. If the backend does **not** validate the file type, your shell is uploaded.
4. Access your shell on the server and execute system commands.

## Key Reminder
> **Client-side validation offers zero real protection—always test backend validation!**

---

**Extra tip:**  
Many real-world apps rely on frontend validation only—don’t trust what you see in the UI. The real battle is always with the server-side checks. Use dev tools and a proxy frequently for maximum control and visibility.