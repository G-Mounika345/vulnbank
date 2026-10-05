pipeline {
    agent any

    environment {
        DC_DATA_DIR    = 'C:/Tools/dependency-check-12.1.0-release/dependency-check/data'
        REPORT_DIR     = 'sca-reports'
        SAST_DIR       = 'sast-reports'
        SONAR_HOST_URL = 'http://localhost:9000'
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Build') {
            steps {
                dir('vulnbank') {
                    bat 'mvn -q -DskipTests compile'
                }
            }
        }

        stage('SCA - OWASP Dependency-Check') {
            steps {
                dir('vulnbank') {
                    withCredentials([string(credentialsId: 'nvd-api-key', variable: 'NVD_API_KEY')]) {
                        script {
                            bat "if not exist ${REPORT_DIR}\\dependency-check mkdir ${REPORT_DIR}\\dependency-check"
                            // Uses the Maven plugin (not the standalone CLI) so it reads the
                            // dependency graph Maven already resolved, instead of fingerprinting
                            // whatever jars happen to sit on disk.
                            //
                            // NOTE: -DoutputDirectory does not relocate the plugin's output in
                            // practice (confirmed on build #5 - it still wrote to target/ despite
                            // the flag), so we let it write to its real default (target/) and copy
                            // the reports out afterwards instead of fighting that.
                            def status = bat(
                                returnStatus: true,
                                script: "mvn org.owasp:dependency-check-maven:12.1.0:check -DprojectName=VulnBank -Dformat=ALL -DdataDirectory=\"%DC_DATA_DIR%\" -DnvdApiKey=%NVD_API_KEY% -DfailBuildOnCVSS=11 -DossindexAnalyzerEnabled=false"
                            )
                            bat "copy /Y target\\dependency-check-report.* ${REPORT_DIR}\\dependency-check\\ >nul"
                            if (status != 0) {
                                unstable("Dependency-Check exited with status ${status}")
                            }
                        }
                    }
                }
            }
        }

        stage('SCA - Snyk') {
            steps {
                dir('vulnbank') {
                    script {
                        try {
                            withCredentials([string(credentialsId: 'snyk-token', variable: 'SNYK_TOKEN')]) {
                                bat "mkdir ${REPORT_DIR}\\snyk 2>nul & exit 0"
                                bat "snyk auth %SNYK_TOKEN%"
                                def status = bat(
                                    returnStatus: true,
                                    script: "snyk test --json-file-output=${REPORT_DIR}\\snyk\\snyk-report.json"
                                )
                                bat "snyk-to-html -i ${REPORT_DIR}\\snyk\\snyk-report.json -o ${REPORT_DIR}\\snyk\\snyk-report.html"
                                if (status != 0) {
                                    unstable("Snyk found vulnerabilities (exit ${status})")
                                }
                                // Publishes a snapshot to the Snyk web dashboard (snyk test alone
                                // is a one-off CLI scan and never creates a dashboard project).
                                // Prints the dashboard URL to console for the SCA email/report.
                                bat "snyk monitor --project-name=VulnBank > ${REPORT_DIR}\\snyk\\snyk-monitor.log 2>&1"
                                archiveArtifacts artifacts: "${REPORT_DIR}/snyk/snyk-monitor.log", allowEmptyArchive: true
                            }
                        } catch (org.jenkinsci.plugins.credentialsbinding.impl.CredentialNotFoundException e) {
                            echo "Skipping Snyk stage: 'snyk-token' credential not configured yet."
                            unstable("Snyk stage skipped - no token configured")
                        }
                    }
                }
            }
        }

        stage('SAST - Semgrep') {
            steps {
                dir('vulnbank') {
                    script {
                        bat "if not exist ${SAST_DIR}\\semgrep mkdir ${SAST_DIR}\\semgrep"
                        // Delete any previous output file before each run. Root cause of the
                        // recurring "[Errno 13] Permission denied" on --output: the existing
                        // semgrep-results.json carries a stale Windows ACL (BUILTIN\Users:
                        // Read+Execute only, no Write) from however it was first created, and
                        // Docker's bind-mount write is blocked trying to overwrite it in place -
                        // even running the container as root doesn't help, since that ACL is
                        // enforced on the Windows host side, outside the container's user
                        // namespace entirely. The parent directory's ACL *does* grant Users
                        // write access, so removing the stale file first lets Docker create a
                        // brand-new one that correctly inherits the directory's permissions.
                        bat "if exist ${SAST_DIR}\\semgrep\\semgrep-results.json del ${SAST_DIR}\\semgrep\\semgrep-results.json"
                        // Semgrep only exists as a per-user pip install on this host, which the
                        // Jenkins service (running as SYSTEM) can't see - Python's user
                        // site-packages resolution is tied to the calling account's profile.
                        // Running it via the official Docker image sidesteps that entirely.
                        def status = bat(
                            returnStatus: true,
                            script: "docker run --rm -v \"%WORKSPACE%\\vulnbank:/src\" semgrep/semgrep semgrep scan --config=p/owasp-top-ten --config=p/security-audit --config=p/java --json --output=/src/${SAST_DIR}/semgrep/semgrep-results.json /src/src"
                        )
                        if (fileExists("${SAST_DIR}/semgrep/semgrep-results.json")) {
                            bat "node ..\\scripts\\build-semgrep-report.js ${SAST_DIR}\\semgrep\\semgrep-results.json . ${SAST_DIR}\\semgrep\\semgrep-report.html"
                        }
                        if (status != 0) {
                            unstable("Semgrep exited with status ${status}")
                        }
                    }
                }
            }
        }

        stage('SAST - SonarQube') {
            steps {
                dir('vulnbank') {
                    withCredentials([string(credentialsId: 'sonarqube-token', variable: 'SONAR_TOKEN')]) {
                        script {
                            def scanStatus = bat(
                                returnStatus: true,
                                script: "mvn -q org.sonarsource.scanner.maven:sonar-maven-plugin:sonar -Dsonar.host.url=%SONAR_HOST_URL% -Dsonar.token=%SONAR_TOKEN% -Dsonar.projectKey=vulnbank -Dsonar.projectName=VulnBank"
                            )
                            // returnStatus: true here too - previously this was a bare `bat`
                            // call, so when SonarQube was unreachable (ECONNREFUSED) the node
                            // script's nonzero exit threw a hard pipeline exception instead of
                            // degrading gracefully like every other optional scanner stage,
                            // which is why the whole build ended FAILURE instead of UNSTABLE.
                            def fetchStatus = bat(
                                returnStatus: true,
                                script: "node ..\\scripts\\fetch-sonarqube-data.js %SONAR_HOST_URL% %SONAR_TOKEN% vulnbank ${SAST_DIR}\\sonarqube"
                            )
                            if (fetchStatus == 0 && fileExists("${SAST_DIR}/sonarqube/sonarqube-issues-raw.json")) {
                                bat "node ..\\scripts\\build-sonarqube-report.js ${SAST_DIR}\\sonarqube\\sonarqube-issues-raw.json ${SAST_DIR}\\sonarqube\\sonarqube-rules-raw.json ${SAST_DIR}\\sonarqube\\sonarqube-measures-raw.json vulnbank %SONAR_HOST_URL% ${SAST_DIR}\\sonarqube\\sonarqube-report.html"
                            }
                            if (scanStatus != 0) {
                                unstable("SonarQube scan exited with status ${scanStatus}")
                            }
                            if (fetchStatus != 0) {
                                unstable("Fetching SonarQube issue data failed with status ${fetchStatus}")
                            }
                        }
                    }
                }
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'vulnbank/sca-reports/**,vulnbank/sast-reports/**', fingerprint: true, allowEmptyArchive: true
            script {
                if (fileExists('vulnbank/sast-reports/semgrep/semgrep-report.html')) {
                    publishHTML(target: [
                        reportDir: 'vulnbank/sast-reports/semgrep',
                        reportFiles: 'semgrep-report.html',
                        reportName: 'Semgrep Report',
                        alwaysLinkToLastBuild: true,
                        keepAll: true
                    ])
                } else {
                    echo 'No Semgrep report found - skipping publishHTML.'
                }
                if (fileExists('vulnbank/sast-reports/sonarqube/sonarqube-report.html')) {
                    publishHTML(target: [
                        reportDir: 'vulnbank/sast-reports/sonarqube',
                        reportFiles: 'sonarqube-report.html',
                        reportName: 'SonarQube Report',
                        alwaysLinkToLastBuild: true,
                        keepAll: true
                    ])
                } else {
                    echo 'No SonarQube report found - skipping publishHTML.'
                }
                if (fileExists('vulnbank/sca-reports/dependency-check/dependency-check-report.html')) {
                    publishHTML(target: [
                        reportDir: 'vulnbank/sca-reports/dependency-check',
                        reportFiles: 'dependency-check-report.html',
                        reportName: 'Dependency-Check Report',
                        alwaysLinkToLastBuild: true,
                        keepAll: true
                    ])
                } else {
                    echo 'No Dependency-Check report found - skipping publishHTML.'
                }
                if (fileExists('vulnbank/sca-reports/snyk/snyk-report.html')) {
                    publishHTML(target: [
                        reportDir: 'vulnbank/sca-reports/snyk',
                        reportFiles: 'snyk-report.html',
                        reportName: 'Snyk Report',
                        alwaysLinkToLastBuild: true,
                        keepAll: true
                    ])
                } else {
                    echo 'No Snyk report found - skipping publishHTML.'
                }

                bat "node scripts\\build-email-report.js vulnbank\\sca-reports\\dependency-check\\dependency-check-report.json vulnbank\\sca-reports\\snyk\\snyk-report.json email-body.html \"${env.BUILD_URL}\" \"${env.BUILD_NUMBER}\" \"${currentBuild.currentResult}\" vulnbank\\sast-reports\\semgrep\\semgrep-results.json vulnbank\\sast-reports\\sonarqube\\sonarqube-issues-raw.json \"${env.SONAR_HOST_URL}/dashboard?id=vulnbank\""
                if (fileExists('email-body.html')) {
                    // emailext (plugin) reliably failed here with "Not sent to
                    // the following valid addresses" across multiple builds even
                    // though identical raw SMTP sends always succeeded - bypassing
                    // it and sending directly via PowerShell's Send-MailMessage.
                    withCredentials([usernamePassword(credentialsId: 'gmail-smtp', usernameVariable: 'GMAIL_USER', passwordVariable: 'GMAIL_PASS')]) {
                        powershell "& scripts\\send-email.ps1 -Username \$env:GMAIL_USER -Password \$env:GMAIL_PASS -To 'alohawork811@gmail.com' -Subject 'VulnBank Security Scan Report - Build #${env.BUILD_NUMBER} - ${currentBuild.currentResult}' -BodyPath 'email-body.html'"
                    }
                } else {
                    echo 'email-body.html not generated - skipping email.'
                }
            }
        }
    }
}
