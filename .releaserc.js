module.exports = {
    branches: [
        {name: "main"},
        {name: "next", prerelease: true},
    ],
    plugins: [
        ["@semantic-release/commit-analyzer", {
            preset: "conventionalcommits"
        }],
        ["@semantic-release/release-notes-generator", {
            preset: "conventionalcommits"
        }],
        "@semantic-release/github"
    ]
};
