/**
 * encryptionLogic.js (Web Version)
 */

const CipherLogic = (() => {
    // Utility: Hash a password into a predictable array of numbers
    function hashPassword(password) {
        if (!password) password = "default_secure_key";
        let hash = 0;
        for (let i = 0; i < password.length; i++) {
            hash = (hash << 5) - hash + password.charCodeAt(i);
            hash |= 0;
        }
        const bytes = [];
        let temp = Math.abs(hash);
        for (let i = 0; i < 4; i++) {
            bytes.push(temp & 255);
            temp >>= 8;
        }
        for (let i = 4; i < 16; i++) {
            bytes.push((bytes[i - 1] * 1103515245 + 12345) % 256);
        }
        return bytes;
    }

    function strToBytes(str) {
        const bytes = [];
        for (let i = 0; i < str.length; i++) {
            const code = str.charCodeAt(i);
            bytes.push(code & 255);
            bytes.push((code >> 8) & 255);
        }
        return bytes;
    }

    function bytesToStr(bytes) {
        let str = '';
        for (let i = 0; i < bytes.length; i += 2) {
            if (i + 1 < bytes.length) {
                str += String.fromCharCode(bytes[i] | (bytes[i + 1] << 8));
            }
        }
        return str;
    }

    const BASE64_CUSTOM = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_";
    function bytesToBase62(bytes) {
        let result = '';
        let buffer = 0;
        let bitsLeft = 0;
        for (let i = 0; i < bytes.length; i++) {
            buffer = (buffer << 8) | bytes[i];
            bitsLeft += 8;
            while (bitsLeft >= 6) {
                bitsLeft -= 6;
                result += BASE64_CUSTOM[(buffer >> bitsLeft) & 63];
            }
        }
        if (bitsLeft > 0) {
            result += BASE64_CUSTOM[(buffer << (6 - bitsLeft)) & 63];
        }
        return result;
    }

    function base62ToBytes(str) {
        const bytes = [];
        let buffer = 0;
        let bitsLeft = 0;
        for (let i = 0; i < str.length; i++) {
            const val = BASE64_CUSTOM.indexOf(str[i]);
            if (val === -1) continue;
            buffer = (buffer << 6) | val;
            bitsLeft += 6;
            if (bitsLeft >= 8) {
                bitsLeft -= 8;
                bytes.push((buffer >> bitsLeft) & 255);
            }
        }
        return bytes;
    }

    // Method A Helper
    function encryptA(text, password) {
        const bytes = strToBytes(text);
        const keyStream = hashPassword(password);
        const encrypted = [];
        let shiftOffset = keyStream[0] % 10;
        for (let i = 0; i < bytes.length; i++) {
            const keyByte = keyStream[i % keyStream.length];
            const encByte = ((bytes[i] ^ keyByte) + shiftOffset) % 256;
            encrypted.push(encByte);
            shiftOffset = (shiftOffset + 3) % 256;
        }
        return bytesToBase62(encrypted);
    }

    function decryptA(encodedText, password) {
        const bytes = base62ToBytes(encodedText);
        const keyStream = hashPassword(password);
        const decrypted = [];
        let shiftOffset = keyStream[0] % 10;
        for (let i = 0; i < bytes.length; i++) {
            const keyByte = keyStream[i % keyStream.length];
            let decByte = (bytes[i] - shiftOffset);
            if (decByte < 0) decByte += 256;
            decByte = decByte ^ keyByte;
            decrypted.push(decByte);
            shiftOffset = (shiftOffset + 3) % 256;
        }
        return bytesToStr(decrypted);
    }

    // Method B Helper
    function shuffleArray(array, seedArray) {
        let seedIndex = 0;
        for (let i = array.length - 1; i > 0; i--) {
            const j = (seedArray[seedIndex % seedArray.length] + i) % (i + 1);
            [array[i], array[j]] = [array[j], array[i]];
            seedIndex++;
        }
    }

    function unshuffleArray(array, seedArray) {
        const swaps = [];
        let sIdx = 0;
        for (let i = array.length - 1; i > 0; i--) {
            const j = (seedArray[sIdx % seedArray.length] + i) % (i + 1);
            swaps.push([i, j]);
            sIdx++;
        }
        for (let i = swaps.length - 1; i >= 0; i--) {
            const [a, b] = swaps[i];
            [array[a], array[b]] = [array[b], array[a]];
        }
    }

    function encryptB(text, password) {
        let bytes = strToBytes(text);
        const keyStream = hashPassword(password);
        for (let i = 0; i < bytes.length; i++) {
            bytes[i] = bytes[i] ^ (~keyStream[i % keyStream.length] & 255);
        }
        const padLength = 16 - (bytes.length % 16);
        if (padLength < 16) {
            for (let i = 0; i < padLength; i++) {
                bytes.push(keyStream[i % keyStream.length]);
            }
        }
        shuffleArray(bytes, keyStream);
        const origLen = text.length * 2;
        const origLenStr = String(origLen).padStart(6, '0');
        const headerBytes = [];
        for (let i = 0; i < origLenStr.length; i++) headerBytes.push(origLenStr.charCodeAt(i));
        return bytesToBase62([...headerBytes, ...bytes]);
    }

    function decryptB(encodedText, password) {
        let allBytes = base62ToBytes(encodedText);
        const keyStream = hashPassword(password);
        if (allBytes.length < 6) throw new Error("Decryption Error");
        let lenStr = '';
        for (let i = 0; i < 6; i++) lenStr += String.fromCharCode(allBytes[i]);
        const origLen = parseInt(lenStr, 10);
        if (isNaN(origLen)) throw new Error("Decryption Error");
        let bytes = allBytes.slice(6);
        unshuffleArray(bytes, keyStream);
        bytes = bytes.slice(0, origLen);
        for (let i = 0; i < bytes.length; i++) {
            bytes[i] = bytes[i] ^ (~keyStream[i % keyStream.length] & 255);
        }
        return bytesToStr(bytes);
    }

    // Method C Helper
    function pseudoRandomByte(seedObj) {
        seedObj.val = (seedObj.val * 9301 + 49297) % 233280;
        return Math.floor((seedObj.val / 233280) * 256);
    }

    function encryptC(text, password) {
        const originalBytes = strToBytes(text);
        const len = originalBytes.length;
        const lenBytes = [(len >> 24) & 255, (len >> 16) & 255, (len >> 8) & 255, len & 255];
        const bytes = [...lenBytes, ...originalBytes];
        const keyStream = hashPassword(password);
        const seed = keyStream.reduce((acc, val) => acc + val, 0);
        const prng = { val: seed || 12345 };
        const output = [];
        let byteIdx = 0;
        let keyIdx = 0;
        while (byteIdx < bytes.length) {
            const gap = (keyStream[keyIdx % keyStream.length] % 4) + 1;
            keyIdx++;
            for (let i = 0; i < gap; i++) output.push(pseudoRandomByte(prng));
            const actualByte = (bytes[byteIdx] + keyStream[keyIdx % keyStream.length]) % 256;
            output.push(actualByte);
            byteIdx++;
            keyIdx++;
        }
        const endNoise = (keyStream[0] % 10) + 5;
        for (let i = 0; i < endNoise; i++) output.push(pseudoRandomByte(prng));
        return bytesToBase62(output);
    }

    function decryptC(encodedText, password) {
        const allBytes = base62ToBytes(encodedText);
        const keyStream = hashPassword(password);
        const seed = keyStream.reduce((acc, val) => acc + val, 0);
        const prng = { val: seed || 12345 };
        const decryptedBytes = [];
        let outIdx = 0;
        let keyIdx = 0;
        while (outIdx < allBytes.length) {
            const gap = (keyStream[keyIdx % keyStream.length] % 4) + 1;
            keyIdx++;
            for (let i = 0; i < gap; i++) {
                pseudoRandomByte(prng);
                outIdx++;
            }
            if (outIdx >= allBytes.length) break;
            let actualByte = (allBytes[outIdx] - keyStream[keyIdx % keyStream.length]);
            if (actualByte < 0) actualByte += 256;
            decryptedBytes.push(actualByte);
            outIdx++;
            keyIdx++;
            if (decryptedBytes.length === 4) break;
        }
        if (decryptedBytes.length < 4) throw new Error("Decryption Error");
        const len = (decryptedBytes[0] << 24) | (decryptedBytes[1] << 16) | (decryptedBytes[2] << 8) | decryptedBytes[3];
        const finalDecrypted = [];
        for (let j = 0; j < len; j++) {
            if (outIdx >= allBytes.length) break;
            const gap = (keyStream[keyIdx % keyStream.length] % 4) + 1;
            keyIdx++;
            for (let i = 0; i < gap; i++) {
                pseudoRandomByte(prng);
                outIdx++;
            }
            if (outIdx >= allBytes.length) break;
            let actualByte = (allBytes[outIdx] - keyStream[keyIdx % keyStream.length]);
            if (actualByte < 0) actualByte += 256;
            finalDecrypted.push(actualByte);
            outIdx++;
            keyIdx++;
        }
        return bytesToStr(finalDecrypted);
    }

    return {
        encrypt: (method, text, password) => {
            switch (method) {
                case 'A': return encryptA(text, password);
                case 'B': return encryptB(text, password);
                case 'C': return encryptC(text, password);
                default: throw new Error("Unknown Method");
            }
        },
        decrypt: (method, text, password) => {
            switch (method) {
                case 'A': return decryptA(text, password);
                case 'B': return decryptB(text, password);
                case 'C': return decryptC(text, password);
                default: throw new Error("Unknown Method");
            }
        }
    };
})();
