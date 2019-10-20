#pragma once

#include <curl/curl.h>

#include "pkgfile.hh"
#include "repo.hh"

namespace pkgfile {

class Updater {
 public:
  Updater(std::string cachedir, int compress);
  ~Updater();

  int Update(const std::string& alpm_config_file, bool force);

 private:
  int DownloadQueueRequest(CURLM* multi, struct Repo* repo);
  void DownloadWaitLoop(CURLM* multi);
  int DownloadCheckComplete(CURLM* multi, int remaining);
  bool RepackRepoData(const struct Repo* repo);

  std::string cachedir_;
  int compress_;
  CURLM* curl_multi_;
};

}  // namespace pkgfile

/* vim: set ts=2 sw=2 et: */
