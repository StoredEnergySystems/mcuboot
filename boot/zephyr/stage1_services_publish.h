/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef STAGE1_SERVICES_PUBLISH_H_
#define STAGE1_SERVICES_PUBLISH_H_

/**
 * Write the Stage 1 services-API locator into the bl_shared_data area.
 * Call once, after boot_go() succeeds and before do_boot(). No-op-safe to
 * call when CONFIG_BOOT_STAGE1_SERVICES_API is disabled only if the caller
 * guards it - this symbol only exists when that option is set.
 */
void stage1_services_publish(void);

#endif /* STAGE1_SERVICES_PUBLISH_H_ */
