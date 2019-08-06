module.exports = {
    "env": {
        "node": true,
        "mocha": true,
        "es6": true
    },
    "plugins":[
        "mocha"
    ],
    "extends": "eslint:recommended",
    "parserOptions": {
        "ecmaVersion":2018,
        "sourceType": "module"
    },
    "rules": {
        "indent": [
            "error",
            "tab"
        ],
        "linebreak-style": [
            "error",
            "unix"
        ],
        "quotes": [
            "error",
            "single"
        ],
        "semi": [
            "error",
            "never"
        ]
    }
};
