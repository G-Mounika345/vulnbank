pipeline {
    agent any

    environment {
        DEPENDENCY_CHECK = 'C:/Tools/dependency-check-12.1.0-release/dependency-check/bin/dependency-check.bat'
        REPORT_DIR        = 'sca-reports'
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
                            def status = bat(
                                returnStatus: true,
                                script: "\"${DEPENDENCY_CHECK}\" --project VulnBank --scan . --format HTML --format JSON --out ${REPORT_DIR}\\dependency-check --nvdApiKey %NVD_API_KEY% --failOnCVSS 999"
                            )
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
                            }
                        } catch (org.jenkinsci.plugins.credentialsbinding.impl.CredentialNotFoundException e) {
                            echo "Skipping Snyk stage: 'snyk-token' credential not configured yet."
                            unstable("Snyk stage skipped - no token configured")
                        }
                    }
                }
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'vulnbank/sca-reports/**', fingerprint: true, allowEmptyArchive: true
            script {
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
            }
        }
    }
}
