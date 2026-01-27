/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

/* javascript functions declared to "use strict" to execute in strict mode.
 * JS methods are put under the "ejbca.ra" namespace and only expose
 * those used explicitly by the RA pages.
 * I.e. methods has to called by ejbca.ra.toggleDetails()
 * version: $Id$
 *
 * Modernized: Using ES6+ features (const/let, arrow functions)
 */
(function() {
    "use strict";

    // Executed when the document has been loaded
    document.addEventListener("DOMContentLoaded", () => {
        console.log("Document loaded.");
        touchUpDocument();
        handleAutoFocus();
        new SessionKeepAlive("sessionKeepAliveLink");
    }, false);

    /** Create a file input element with id "newElementId" as child to the "appendToElementId". */
    const createInputFileElement = (newElementId, appendToElementId, onUploadFinishedCallback) => {
        if (document.getElementById(newElementId)) {
            console.log(`ejbca.ra.createFileUploadInput: Element '${newElementId}' already exists.`);
            return;
        }
        if (!document.getElementById(appendToElementId)) {
            console.log(`ejbca.ra.createFileUploadInput: Element '${appendToElementId}' does not exist.`);
            return;
        }
        const inputFileElement = document.createElement("input");
        inputFileElement.type = "file";
        inputFileElement.id = newElementId;
        inputFileElement.onchange = () => {
            if (inputFileElement.files.length !== 0) {
                const fileReader = new FileReader();
                fileReader.onloadend = (event) => {
                    if (event.target.readyState === FileReader.DONE) {
                        let b64str = '';
                        if (onUploadFinishedCallback) {
                            const bytes = new Uint8Array(event.target.result);
                            const len = bytes.byteLength;
                            for (let i = 0; i < len; i++) {
                                b64str += String.fromCharCode(bytes[i]);
                            }
                            if (!b64str.includes("-----BEGIN CERTIFICATE REQUEST-----")) {
                                // This is not a PEM request, encode b64
                                b64str = window.btoa(b64str);
                            }
                            onUploadFinishedCallback(b64str);
                        }
                        inputFileElement.value = '';
                    }
                };
                fileReader.readAsArrayBuffer(inputFileElement.files[0]);
            }
        };
        document.getElementById(appendToElementId).appendChild(inputFileElement);
    };

    /** Look for tagged objects and make the page nicer when JS is available */
    const touchUpDocument = () => {
        // Hide elements that should not be shown when JS is enabled
        forEachInputElementByTagNameAndStyleClass(["input", "label", "select"], "jsHide", (inputField) => {
            inputField.style.display = "none";
        });
        // Show elements that should not be hidden when JS is disabled
        forEachInputElementByTagNameAndStyleClass(["input", "label", "select"], "jsShow", (inputField) => {
            inputField.style.display = "inherit";
        });
        // Use title as HTML5 placeholder for elements marked with the style class
        forEachInputElementByTagNameAndStyleClass(["input", "textarea"], "jsTitleAsPlaceHolder", (inputField) => {
            inputField.placeholder = inputField.title;
            inputField.title = "";
        });
        // Delay "keyup" events for input elements marked with the provided styleClassName (JSF AJAX workaround)
        forEachInputElementByTagNameAndStyleClass(["input"], "jsDelayKeyUp", (inputField) => {
            new KeyUpEventDelay(inputField, 400);
        });
        // Prevent Enter key press event propagation for input elements marked with the provided styleClassName
        forEachInputElementByTagNameAndStyleClass(["input"], "jsPreventEnterKeyPropagation", (inputField) => {
            new PreventEnterKeyEventPropagation(inputField);
        });
    };

    /** Set focus to component by class names (JSF does not support HTML5 attributes like autofocus) */
    const handleAutoFocus = () => {
        const focusElementTypes = ["a", "input", "textarea", "select"];
        // Auto focus last found element tagged "jsAutoFocusLast"
        forEachInputElementByTagNameAndStyleClass(focusElementTypes, "jsAutoFocusLast", (inputField) => {
            inputField.focus();
            return true;
        }, true);
        // Auto focus last found element tagged "jsAutoFocusFirst" (overriding previously set focus)
        forEachInputElementByTagNameAndStyleClass(focusElementTypes, "jsAutoFocusFirst", (inputField) => {
            inputField.focus();
            return true;
        });
        // Auto focus last found element tagged "jsAutoFocusJsf" (overriding previously set focus)
        forEachInputElementByTagNameAndStyleClass(focusElementTypes, "jsAutoFocusJsf", (inputField) => {
            inputField.focus();
            return true;
        });
        // Auto focus first found element tagged "jsAutoFocusError" (overriding previously set focus)
        forEachInputElementByTagNameAndStyleClass(focusElementTypes, "jsAutoFocusError", (inputField) => {
            inputField.focus();
            return true;
        });
    };

    /** Process the callback on each input element that matches the provided style class. */
    function forEachInputElementByTagNameAndStyleClass(elementTagNames, styleClassName, callback, reverse) {
        for (let k = 0; k < elementTagNames.length; k++) {
            const elementTagName = elementTagNames[k];
            const inputFields = document.getElementsByTagName(elementTagName);
            for (let i = (reverse ? inputFields.length - 1 : 0); (reverse ? i >= 0 : i < inputFields.length); (reverse ? i-- : i++)) {
                if (inputFields[i].className) {
                    const styleClasses = inputFields[i].className.split(' ');
                    for (let j = 0; j < styleClasses.length; j++) {
                        if (styleClasses[j] === styleClassName) {
                            if (callback(inputFields[i])) {
                                return;
                            }
                            // Remove the class name to avoid processing it multiple times if this method is invoked again
                            inputFields[i].className = inputFields[i].className.replace(styleClassName, "").trim();
                            // Invoke the callback with the matching element. If it returns true we stop looking for more elements.
                            break;
                        }
                    }
                }
            }
        }
    }

    /**
     * Keep JSF session alive by polling back-end before the session has expired.
     *
     * @param linkElementId ID of a-element pointing to keep alive link.
     */
    function SessionKeepAlive(linkElementId) {
        const instance = this;
        this.timeToNextCheckInMs = 100; // Make first check after 100 ms.
        this.xmlHttpReq = new XMLHttpRequest();
        const linkComponent = document.getElementById(linkElementId);
        if (linkComponent) {
            this.link = linkComponent.getAttribute("href");
        }
        this.xmlHttpReq.onreadystatechange = () => {
            if (instance.xmlHttpReq.readyState === 4) {
                if (instance.xmlHttpReq.status === 200) {
                    instance.timeToNextCheckInMs = instance.xmlHttpReq.responseText;
                    window.setTimeout(instance.poll, instance.timeToNextCheckInMs);
                } else {
                    console.log(`SessionKeepAlive failed with HTTP status code ${instance.xmlHttpReq.status}`);
                }
            }
        };
        this.poll = () => {
            instance.xmlHttpReq.open("GET", instance.link, true);
            try {
                instance.xmlHttpReq.send();
            } catch (exception) {
                console.log(`SessionKeepAlive failed: ${exception}`);
            }
        };
        if (this.link) {
            window.setTimeout(this.poll, this.timeToNextCheckInMs);
        } else {
            console.log(`Unable to find link element with ID '${linkElementId}'. SessionKeepAlive will not be enabled.`);
        }
    }

    /**
     * Delays "onkeyup" event handler invocation while additional events are triggered.
     *
     * @param inputElement the element to wrap the onkeyup handler for
     * @param timeoutMs delay in milliseconds
     */
    function KeyUpEventDelay(inputElement, timeoutMs) {
        const instance = this;
        this.component = inputElement;
        this.originalHandler = inputElement.onkeyup;
        this.timeout = timeoutMs;
        this.timer = 0;

        this.delay = (event) => {
            // Reschedule (prevent) any existing timeout to the original handler and schedule a new one
            window.clearTimeout(instance.timer);
            instance.timer = window.setTimeout(() => {
                instance.originalHandler.call(instance.component, event);
            }, instance.timeout);
        };

        if (this.originalHandler) {
            this.component.onkeyup = this.delay;
        }
    }

    /**
     * Prevent propagation of the Enter key press event to other elements.
     *
     * @param inputElement the element to wrap the keypress handler for
     */
    function PreventEnterKeyEventPropagation(inputElement) {
        inputElement.addEventListener('keypress', (e) => {
            if (e.key === 'Enter' || e.keyCode === 13) {
                e.preventDefault();
                e.stopPropagation();
            }
        });
    }

    /** Can be invoked on AJAX requests to indicate that a background operation is running. */
    const onAjaxEvent = (data, elementId) => {
        const element = document.getElementById(elementId);
        if (!element) return;
        if (data.status === "begin") {
            element.style.opacity = "0.2";
        } else if (data.status === "success") {
            element.style.opacity = "1.0";
        }
    };

    /** Can be invoked on AJAX requests to indicate that an error has occurred. */
    const onAjaxError = (data, elementId) => {
        console.log(`onAjaxError: ${data.errorMessage}`);
        const element = document.getElementById(elementId);
        if (element) {
            element.style.opacity = "0.2";
        }
    };

    /**
     * Toggle visibility of details section
     */
    function toggleDetails(element, show, hide) {
        const detailsId = element.id + 'Details';
        const details = document.getElementById(detailsId);
        if (!details) return;

        if (details.style.display === 'none') {
            details.style.display = 'block';
            element.value = hide;
        } else {
            details.style.display = 'none';
            element.value = show;
        }
    }

    /**
     * Toggle visibility of multiple elements
     */
    const toggleElements = (visible, elements, visibleState = 'inline-block') => {
        for (let i = 0; i < elements.length; i++) {
            const elem = document.getElementById(elements[i]);
            if (elem) {
                elem.style.display = visible ? visibleState : 'none';
            }
        }
    };

    /**
     * Programmatically click an element by ID
     */
    function click(id) {
        const element = document.getElementById(id);
        if (element) {
            element.click();
        }
    }

    /**
     * Grow element to its content height (for textareas)
     */
    function growToContentHeight(id) {
        const element = document.getElementById(id);
        if (element) {
            element.style.height = `${element.scrollHeight}px`;
        }
    }

    // Setup name space...
    window.ejbca = window.ejbca || {};
    ejbca.ra = ejbca.ra || {};
    // ...and expose API functions under this name space.
    ejbca.ra.createFileUploadInput = createInputFileElement;
    ejbca.ra.touchUpDocument = touchUpDocument;
    ejbca.ra.handleAutoFocus = handleAutoFocus;
    ejbca.ra.onAjaxEvent = onAjaxEvent;
    ejbca.ra.onAjaxError = onAjaxError;
    ejbca.ra.toggleDetails = toggleDetails;
    ejbca.ra.toggleElements = toggleElements;
    ejbca.ra.click = click;
    ejbca.ra.growToContentHeight = growToContentHeight;
}());
